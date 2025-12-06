using GdeWebDB.Interfaces;
using GdeWebDB.Services;
using GdeWebDB.Utilities;
using GdeWebModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Annotations;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mime;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace GdeWebAPI.Controllers
{
    /// <summary>
    /// Felhasználók hitelesítéséért és jogosultsági tokenek kezeléséért felelős API vezérlő.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [DisableRateLimiting] // Az egész controllerre érvényes, hogy nincs Rate Limiting
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        private readonly IAuthService _authService;

        private readonly ILogService _logService;

        /// <summary>
        /// Létrehozza az <see cref="AuthController"/> példányt a szükséges szolgáltatásokkal.
        /// </summary>
        /// <param name="configuration">Az alkalmazás konfigurációs beállításai.</param>
        /// <param name="authService">A felhasználók hitelesítéséért felelős szolgáltatás.</param>
        /// <param name="logService">A naplózási műveletekért felelős szolgáltatás.</param>
        public AuthController(IConfiguration configuration, IAuthService authService, ILogService logService)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(authService);
            ArgumentNullException.ThrowIfNull(logService);

            this._configuration = configuration;
            this._authService = authService;
            this._logService = logService;
        }

        /// <summary>
        /// Felhasználó bejelentkeztetése. Sikeres hitelesítés esetén JWT tokent ad vissza.
        /// </summary>
        /// <param name="credential">A bejelentkezéshez szükséges adatok (felhasználónév, jelszó).</param>
        /// <returns>
        /// 200 OK – érvényes tokennel, ha a bejelentkezés sikeres.  
        /// 401 Unauthorized – ha a hitelesítés sikertelen.
        /// </returns>
        [HttpPost]
        [Route("Login")]
        [ApiExplorerSettings(IgnoreApi = true)] // [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Bejelentkezés felhasználónévvel és jelszóval",
            Description = "LoginResultModel = Login(LoginModel credentials)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task <LoginResultModel> Login([FromBody] LoginModel credential)
        {
            // SHA - 512 jelszó hashelés
            //LoginModel encryptedCredentials = new LoginModel
            //{
            //    Email = credential.Email,
            //    Password = Utilities.Utilities.EncryptPassword(credential.Password)
            //};

            LoginResultModel loginResult = await _authService.Login(credential);

            if (loginResult.Result.Success)
            {
                // Token generálás
                string token = Utilities.Utilities.GenerateToken(loginResult, _configuration);

                loginResult.Token = token;

                double time = Convert.ToDouble(_configuration["Jwt:ExpireMinutes"]);

                ResultModel resultModel = await _authService.AddUserTokenExpirationDate(loginResult.Id, token, DateTime.Now.AddHours(time));
            }

            return loginResult;
        }

        /// <summary>
        /// Visszaadja a felhasználó adatait egy meglévő hitelesítési token alapján.
        /// </summary>
        /// <param name="token">A token értékét tartalmazó modell.</param>
        /// <returns>
        /// 200 OK – ha a token érvényes és a felhasználó azonosítható.  
        /// 401 Unauthorized – ha a token érvénytelen vagy lejárt.
        /// </returns>
        [HttpPost]
        [Route("GetUserFromToken")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Bejelentkezés tokennel",
            Description = "LoginUserModel = GetUserFromToken(LoginTokenModel token)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task<LoginUserModel> GetUserFromToken([FromBody] LoginTokenModel token)
        {
            int userId = Utilities.Utilities.GetUserIdFromToken(token.Token);

            if (userId == -1)
            {
                return new LoginUserModel() { Result = ResultTypes.UserAuthenticateError };
            }

            // CHECK EXPIRATION DATE
            double time = Convert.ToDouble(_configuration["Jwt:ExpireInHours"]);
            ResultModel result = await _authService.GetUserTokenExpirationDate(userId, DateTime.Now.AddHours(time));
            if (!result.Success)
            {
                return new LoginUserModel() { Result = ResultTypes.UserAuthenticateError };
            }

            LoginUserModel user = await _authService.GetUser(userId);
            user.Token = token.Token; // Visszaadja a tokent is

            return user;
        }


        /// Google Auth
        [HttpGet("LoginGoogle")]
        public IActionResult LoginGoogle()
        {
            var props = new Microsoft.AspNetCore.Authentication.AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleCallback")
            };

            return Challenge(props, "Google");
        }

        /// Google Auth
        [HttpGet("GoogleCallback")]
        public async Task<IActionResult> GoogleCallback()
        {
            var authResult = await HttpContext.AuthenticateAsync("Google");

            if (!authResult.Succeeded)
                return Unauthorized("Google auth failed.");

            var claims = authResult.Principal?.Claims;

            var email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var name = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var picture = claims?.FirstOrDefault(c => c.Type == "picture")?.Value;

            if (string.IsNullOrEmpty(email))
                return BadRequest("Google did not return an email.");

            var login = await _authService.LoginWithGoogle(email, name ?? "", picture ?? "");

            if (!login.Result.Success)
                return Unauthorized("User creation/login failed.");

            string token = Utilities.Utilities.GenerateToken(login, _configuration);
            login.Token = token;

            double time = Convert.ToDouble(_configuration["Jwt:ExpireInHours"]);
            await _authService.AddUserTokenExpirationDate(
                login.Id,
                token,
                DateTime.Now.AddHours(time)
            );

            var frontendUrl = _configuration["websiteUrl"] ?? "https://localhost:7294";

            return Redirect($"{frontendUrl}/google-success?token={token}");
        }
    }
}
