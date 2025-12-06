using GdeWebDB.Interfaces;
using GdeWebModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Swashbuckle.AspNetCore.Annotations;
using System.Net.Mime;

namespace GdeWebAPI.Controllers
{
    /// <summary>
    /// E-mail műveletek API vezérlője.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class MailController : ControllerBase
    {
        // FIX TOKEN – csak belső szerver kommunikációhoz
        private const string InternalHeaderName = "InternalAccessToken"; // fix header
        private readonly string _internalToken = ""; // = "TITKOS_BELSO_TOKEN"; // <-- ide írd be a titkos kulcsot

        private bool InternalTokenOk(HttpContext ctx)
        {
            if (ctx.Request.Headers.TryGetValue(InternalHeaderName, out var token))
                return string.Equals(token.ToString(), _internalToken, StringComparison.Ordinal);
            return false;
        }

        private readonly IMailService _mailService;

        private readonly IConfiguration _configuration;

        /// <summary>
        /// Létrehozza az <see cref="MailController"/> példányt a szükséges szolgáltatásokkal.
        /// </summary>
        /// <param name="configuration">Az alkalmazás konfigurációs beállításai.</param>
        /// <param name="mailService">Az email műveletekért felelős szolgáltatás.</param>
        public MailController(IMailService mailService, IConfiguration configuration)
        {
            this._mailService = mailService;
            this._configuration = configuration;
            //_internalToken = configuration["InternalAccessToken"]
            //    ?? throw new InvalidOperationException("Missing InternalAccessToken in configuration");
        }

        /// <summary>
        /// Új kapcsolatfelvételi e-mail küldése.
        /// </summary>
        /// <param name="model">Az e-mail adatai (név, e-mail, üzenet).</param>
        /// <returns>Siker/hiba válasz.</returns>
        [HttpPost]
        [Route("AddContactMail")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Weboldalról érkező email tárolása és küldése",
            Description = "ResultModel = AddContactMail(EmailModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [EnableRateLimiting("MessagePolicy")] // <-- Csak erre a controllerre érvényes
        public async Task<ResultModel> AddContactMail([FromBody] EmailModel model)
        {
            //if (!InternalTokenOk(HttpContext))
            //    return new ResultModel { Success = false, ErrorMessage = "Forbidden: Invalid or missing InternalAccessToken." };

            if (string.IsNullOrEmpty(model.ToEmail))
                model.ToEmail = _configuration["ContactMail"] ?? String.Empty;

            var result = await _mailService.AddContactMail(model);
            return result;
        }
    }
}
