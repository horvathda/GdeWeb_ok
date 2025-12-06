using GdeWebAPI.Middleware;
using GdeWebDB.Interfaces;
using GdeWebDB.Services;
using GdeWebDB.Utilities;
using GdeWebModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Reflection;
using System.Text;

namespace GdeWebAPI.Controllers
{
    /// <summary>
    /// Felhasználók kezeléséért felelős API vezérlő: regisztráció, e-mail megerősítés,
    /// jelszó-emlékeztető, profil- és szerepkör-műveletek.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [DisableRateLimiting] // Az egész controllerre érvényes, hogy nincs Rate Limiting
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        private readonly IAuthService _authService;

        private readonly IMailService _mailService;

        private readonly ILogService _logService;

        private readonly IConfiguration configuration;

        private readonly string wwwrootPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot");

        /// <summary>
        /// Létrehozza a <see cref="UserController"/> példányt a szükséges szolgáltatásokkal.
        /// </summary>
        /// <param name="configuration">Alkalmazás konfiguráció.</param>
        /// <param name="userService">Felhasználói műveletek szolgáltatása.</param>
        /// <param name="authService">Hitelesítési és token szolgáltatás.</param>
        /// <param name="mailService">E-mail küldési szolgáltatás.</param>
        /// <param name="logService">Naplózási szolgáltatás.</param>
        public UserController(IConfiguration configuration, IUserService userService, IAuthService authService, IMailService mailService, ILogService logService)
        {
            this.configuration = configuration;
            this._userService = userService;
            this._authService = authService;
            this._mailService = mailService;
            this._logService = logService;
        }



        // HITELESÍTÉS NÉLKÜL


        /// <summary>
        /// Új felhasználót hoz létre és megerősítő e-mailt küld.
        /// </summary>
        /// <param name="model">A létrehozandó felhasználó adatai.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("AddUser")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Létrehoz egy Felhasználót",
            Description = "ResultModel = AddUser(UserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task<ResultModel> AddUser([FromBody] UserModel model)
        {
            var result = await _userService.AddUser(model);

            if (result.Success)
            {
                LoginResultModel loginResult = await _authService.Auth(new LoginModel() { Email = model.Email, Password = model.Password });

                if (loginResult.Result.Success)
                {
                    string token = Utilities.Utilities.GenerateToken(loginResult, configuration);
                    // get URL
                    var apiUrl = configuration["apiUrl"]
                         ?? throw new InvalidOperationException("Missing 'apiUrl' in configuration.");
                    string url = $"{apiUrl}/api/User/ConfirmationEmail?token={token}";

                    EmailModel emailModel = new EmailModel()
                    {
                        Id = 0,
                        ToEmail = model.Email,
                        Name = model.FirstName + " " + model.LastName,
                        Phone = "",
                        FromEmail = "",
                        Subject = url,
                        Message = "",
                        CreatingDate = DateTime.Now,
                        Result = new ResultModel() { Success = false, ErrorMessage = "" }
                    };

                    ResultModel emailResult = await _mailService.SendConfirmationEmail(emailModel);

                    if (!emailResult.Success)
                    {
                        result.Success = emailResult.Success;
                        result.ErrorMessage = emailResult.ErrorMessage;
                    }
                }
                else
                {
                    result.Success = loginResult.Result.Success;
                    result.ErrorMessage = loginResult.Result.ErrorMessage;
                }
            }

            return result;
        }

        /// <summary>
        /// Elfelejtett jelszó folyamat indítása, e-mail küldéssel.
        /// </summary>
        /// <param name="model">Azonosításhoz szükséges adatok (pl. e-mail).</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("ForgotPassword")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Elfelejtett jelszó küldése email cím alapján",
            Description = "ResultModel = ForgotPassword(ForgotModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task<ResultModel> ForgotPassword([FromBody] ForgotModel model)
        {
            double expirationHours;

            if (double.TryParse(configuration["Jwt:ExpireInHours"], out expirationHours))
            {
                LoginResultModel loginResult = await _authService.Forgot(model);

                if (loginResult.Result.Success)
                {
                    var userResult = await _userService.GetUser(loginResult.Id);

                    if (userResult.Result.Success)
                    {
                        string token = Utilities.Utilities.GenerateToken(loginResult, configuration);
                        // get URL
                        string apiUrl = configuration["apiUrl"] ?? throw new ArgumentNullException();
                        string url = $"{apiUrl}/api/User/ForgotPasswordEmail?token={token}";

                        ResultModel resultModel = await _authService.AddUserTokenExpirationDate(loginResult.Id, token, DateTime.Now.AddHours(expirationHours));

                        if (resultModel.Success)
                        {
                            EmailModel emailModel = new EmailModel()
                            {
                                Id = 0,
                                ToEmail = model.Email,
                                Name = userResult.FirstName + " " + userResult.LastName,
                                Phone = "",
                                FromEmail = "",
                                Subject = url,
                                Message = "",
                                CreatingDate = DateTime.Now,
                                Result = new ResultModel() { Success = false, ErrorMessage = "" }
                            };

                            ResultModel emailResult = await _mailService.SendForgotPasswordEmail(emailModel);

                            return emailResult;
                        }
                        else
                        {
                            return userResult.Result;
                        }
                    }
                    else
                    {
                        return userResult.Result;
                    }
                }
                else
                {
                    return loginResult.Result;
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "The expiration time is not found!" };
            }
        }

        /// <summary>
        /// Elfelejtett jelszó e-mail link kezelése; átirányít a jelszócsere oldalra.
        /// </summary>
        /// <param name="token">A felhasználó azonosítására szolgáló token.</param>
        /// <returns>Átirányítás a felületre vagy hiba.</returns>
        [HttpGet]
        [Route("ForgotPasswordEmail")] // api/User/ConfirmationEmail?token=
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Egy felhasználó elefelejtett jelszavát kezeli, majd a login oldalra lép.",
            Description = "IActionResult = ForgotPasswordEmail()"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task<IActionResult> ForgotPasswordEmail(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return NotFound();
            }

            int userId = Utilities.Utilities.GetUserIdFromToken(token);

            if (userId == -1)
            {
                return NotFound();
            }

            UserModel user = await _userService.GetUser(userId);

            if (!user.Result.Success)
            {
                return NotFound();
            }

            user.Active = true;
            ResultModel result = await _userService.SetUserState(user);

            if (result.Success)
            {
                string websiteUrl = configuration["websiteUrl"] ?? throw new ArgumentNullException();
                //return Redirect($"{websiteUrl}/change-password/{token}"); // ChangePasswordEmail.html -> to login
                return Redirect($"{websiteUrl}/change-password?token={token}"); // ChangePasswordEmail.html -> to login
            }
            else
            {
                return BadRequest(result);
            }
        }


        /// <summary>
        /// E-mail cím megerősítése; átirányít a bejelentkezési felületre.
        /// </summary>
        /// <param name="token">Megerősítési token.</param>
        /// <returns>Átirányítás a felületre vagy hiba.</returns>
        [HttpGet]
        [Route("ConfirmationEmail")] // api/User/ConfirmationEmail?token=
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Hitelesíti egy felhasználó email címét, majd a login oldalra lép.",
            Description = "IActionResult = ConfirmationEmail()"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        public async Task<IActionResult> ConfirmationEmail(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return NotFound();
            }

            int userId = Utilities.Utilities.GetUserIdFromToken(token);

            if (userId == -1)
            {
                return NotFound();
            }

            UserModel user = await _userService.GetUser(userId);

            if (!user.Result.Success)
            {
                return NotFound();
            }

            user.Active = true;
            ResultModel result = await _userService.SetUserState(user);

            // Email küldése a felhasználónak, ha aktiválva / iaktiválva lett
            EmailModel emailModel = new EmailModel()
            {
                Id = 0,
                ToEmail = user.Email,
                Name = user.FirstName + " " + user.LastName,
                Phone = "",
                FromEmail = "",
                Subject = user.FirstName,
                Message = "",
                CreatingDate = DateTime.Now,
                Result = new ResultModel() { Success = false, ErrorMessage = "" }
            };

            ResultModel emailResult = await _mailService.SendConfirmationFinalEmail(emailModel);

            if (!emailResult.Success)
            {
                // Ha az email küldés nem sikerült, akkor logoljuk az error message-t
                Console.WriteLine($"Email küldési hiba: {emailResult.ErrorMessage}");
                await _logService.WriteMessageLogToFile($"Email küldési hiba: {emailResult.ErrorMessage}", "ConfirmationEmail");
            }

            if (result.Success)
            {
                string websiteUrl = configuration["websiteUrl"] ?? throw new ArgumentNullException();
                //return Redirect($"{websiteUrl}/true"); // ConfirmEmail.html -> to login // /signin ? or home -> /
                return Redirect($"{websiteUrl}/signin?confirmation=true"); // ConfirmEmail.html -> to login // /signin ? or home -> /
            }
            else
            {
                return BadRequest(result);
            }
        }



        // HITELESÍTÉSSEL



        /// <summary>
        /// A bejelentkezett felhasználó saját profiladatainak módosítása.
        /// </summary>
        /// <param name="model">A módosított felhasználói adatok.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("ModifyProfile")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosítja a Felhasználó adatatait",
            Description = "ResultModel = ModifyProfile(UserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> ModifyProfile([FromBody] UserModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.ModifyProfile(model);

                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }


        /// <summary>
        /// A bejelentkezett felhasználó jelszavának módosítása.
        /// </summary>
        /// <param name="model">Régi és új jelszó adatai.</param>
        /// <returns>A módosítás eredményét tartalmazó modell.</returns>
        [HttpPost]
        [Route("ModifyProfilePassword")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosítja a Felhasználó jelszavát",
            Description = "ProfilePasswordModel = ModifyProfilePassword(ProfilePasswordModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ProfilePasswordModel> ModifyProfilePassword([FromBody] ProfilePasswordModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.ModifyProfilePassword(model);
                        return result;
                    }
                    else
                    {
                        return new ProfilePasswordModel() { Result = new ResultModel() { Success = false, ErrorMessage = "User is not valid!" } };
                    }
                }
                else
                {
                    return new ProfilePasswordModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." } };
                }
            }
            else
            {
                return new ProfilePasswordModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." } };
            }
        }




        /// <summary>
        /// Felhasználók listájának lekérése.
        /// </summary>
        /// <returns>Felhasználólista eredménnyel.</returns>
        [HttpGet]
        [Route("GetUserList")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Lekérdezi az összes Felhasználót",
            Description = "UserListModel = GetUserList()"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<UserListModel> GetUserList()
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.GetUserList();
                        return result;
                    }
                    else
                    {
                        return new UserListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "User is not valid!" } };
                    }
                }
                else
                {
                    return new UserListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." } };
                }
            }
            else
            {
                return new UserListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." } };
            }
        }

        /// <summary>
        /// Felhasználó módosítása administratív műveletként.
        /// </summary>
        /// <param name="model">A módosítandó felhasználó adatai.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("ModifyUser")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosít egy Felhasználót",
            Description = "ResultModel = ModifyUser(UserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> ModifyUser([FromBody] UserModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.ModifyUser(model);

                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }


        /// <summary>
        /// Felhasználó törlése administratív műveletként.
        /// </summary>
        /// <param name="model">A törlendő felhasználó azonosítója.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("DeleteUser")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Töröl egy Felhasználót",
            Description = "ResultModel = DeleteUser(UserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> DeleteUser([FromBody] UserModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        // User lekérése az Id alapján
                        UserModel user = await _userService.GetUser(model.Id);

                        if (user is not null && user.Id > 0)
                        {
                            // Felhasználó törlése
                            var result = await _userService.DeleteUser(user);

                            return result;
                        }
                        else
                        {
                            return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                        }
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }



        /// <summary>
        /// Felhasználó aktív/inaktív állapotának beállítása, értesítő e-mail küldésével.
        /// </summary>
        /// <param name="model">A felhasználó és az új állapot.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("SetUserState")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosítja egy Felhasználó aktív szerepét",
            Description = "ResultModel = SetUserState(UserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> SetUserState([FromBody] UserModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.SetUserState(model);

                        if (result.Success)
                        {
                            // Email küldése a felhasználónak, ha aktiválva / iaktiválva lett
                            EmailModel emailModel = new EmailModel()
                            {
                                Id = 0,
                                ToEmail = model.Email,
                                Name = model.FirstName + " " + model.LastName,
                                Phone = "",
                                FromEmail = "",
                                Subject = model.FirstName,
                                Message = model.Active ? "Aktív" : "Inaktív",
                                CreatingDate = DateTime.Now,
                                Result = new ResultModel() { Success = false, ErrorMessage = "" }
                            };

                            ResultModel emailResult = await _mailService.SendUserStateEmail(emailModel);

                            if (!emailResult.Success)
                            {
                                // Ha az email küldés nem sikerült, akkor logoljuk az error message-t
                                Console.WriteLine($"Email küldési hiba: {emailResult.ErrorMessage}");
                                await _logService.WriteMessageLogToFile($"Email küldési hiba: {emailResult.ErrorMessage}", "SetUserState");
                                result.Success = false;
                                result.ErrorMessage += $" | Email küldési hiba: {emailResult.ErrorMessage}";
                            }
                        }

                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }

        /// <summary>
        /// Felhasználó tárolt adataihoz kapcsolódó beállítások frissítése.
        /// </summary>
        /// <param name="model">A frissítendő beállítások.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("SetUserData")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosítja egy Felhasználó tárolt adatait",
            Description = "ResultModel = SetUserData(LoginUserModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> SetUserData([FromBody] LoginUserModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.SetUserData(model);
                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }




        /// <summary>
        /// Szerepkörök listájának lekérése.
        /// </summary>
        /// <returns>Szerepkörlista eredménnyel.</returns>
        [HttpGet]
        [Route("GetRoles")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Lekérdezi az összes szerepkört",
            Description = "RoleListModel = GetRoles()"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<RoleListModel> GetRoles()
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.GetRoles();
                        return result;
                    }
                    else
                    {
                        return new RoleListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "User is not valid!" } };
                    }
                }
                else
                {
                    return new RoleListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." } };
                }
            }
            else
            {
                return new RoleListModel() { Result = new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." } };
            }
        }

        /// <summary>
        /// Új szerepkör létrehozása.
        /// </summary>
        /// <param name="model">A szerepkör adatai.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("AddRole")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Létrehoz egy szerepkört",
            Description = "ResultModel = AddRole(RoleModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> AddRole([FromBody] RoleModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.AddRole(model);
                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }

        /// <summary>
        /// Meglévő szerepkör módosítása.
        /// </summary>
        /// <param name="model">A módosított szerepkör adatai.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("ModifyRole")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Módosít egy szerepkört",
            Description = "ResultModel = ModifyRole(RoleModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> ModifyRole([FromBody] RoleModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.ModifyRole(model);
                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }

        /// <summary>
        /// Szerepkör törlése.
        /// </summary>
        /// <param name="model">A törlendő szerepkör azonosítója.</param>
        /// <returns>A művelet eredménye.</returns>
        [HttpPost]
        [Route("DeleteRole")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Töröl egy szerepkört",
            Description = "ResultModel = DeleteRole(RoleModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> DeleteRole([FromBody] RoleModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                string accessToken = accessTokenHeader.ToString();

                int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        var result = await _userService.DeleteRole(model);
                        return result;
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing userId or userGuid." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }
    }
}
