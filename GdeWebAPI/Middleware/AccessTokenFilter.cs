using GdeWebDB.Interfaces;
using GdeWebModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Threading.Tasks;

namespace GdeWebAPI.Middleware
{
    /// <summary>
    /// Action filter, amely ellenőrzi az <c>AccessToken</c> fejlécet,
    /// és a token alapján validálja a felhasználót a védett végpontok előtt.
    /// </summary>
    public class AccessTokenFilter : IAsyncActionFilter
    {
        private readonly IAuthService _authService;

        public AccessTokenFilter(IAuthService authService)
        {
            _authService = authService;
        }

        /// <summary>
        /// A művelet végrehajtása ELŐTT fut le. Ellenőrzi a <c>AccessToken</c> fejlécet,
        /// dekódolja a felhasználó-azonosítókat, és érvényesíti a felhasználót.
        /// Szükség esetén <see cref="Microsoft.AspNetCore.Mvc.ControllerBase.Unauthorized()"/> vagy
        /// <see cref="Microsoft.AspNetCore.Mvc.ControllerBase.Forbid()"/> választ állít be.
        /// </summary>
        /// <param name="context">Az aktuális action végrehajtási kontextusa.</param>
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            // Az action végrehajtása előtt végrehajtandó logika
            // Ellenőrizhetjük a hozzáférési tokent itt
            if (!context.HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                context.Result = new UnauthorizedObjectResult(new { success = false, error = "AccessToken hiányzik." });
                return;
            }

            var accessToken = accessTokenHeader.ToString();
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                context.Result = new UnauthorizedObjectResult(new { success = false, error = "Üres AccessToken." });
                return;
            }

            // Token feldolgozás
            int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
            string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

            if (userId <= 0 || string.IsNullOrWhiteSpace(userGuid))
            {
                context.Result = new UnauthorizedObjectResult(new { success = false, error = "Érvénytelen token." });
                return;
            }

            // Felhasználó validálása
            ResultModel userValid = await _authService.UserValidation(userId, userGuid);
            if (userValid?.Success != true)
            {
                context.Result = new ForbidResult(); // üzenet nélkül
                return;
            }

            // Minden oké → folytatás
            await next();
        }

        /// <summary>
        /// A művelet végrehajtása UTÁN fut le. Itt naplózható az eredmény vagy
        /// kiegészítő header állítható be.
        /// </summary>
        /// <param name="context">Az aktuális action végrehajtási kontextusa a végrehajtás után.</param>
        public void OnActionExecuted(ActionExecutedContext context)
        {
            // Az action végrehajtása után végrehajtandó logika
        }
    }
}
