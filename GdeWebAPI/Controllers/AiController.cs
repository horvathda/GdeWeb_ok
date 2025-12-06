using GdeWebAPI.Middleware;
using GdeWebAPI.Services;
using GdeWebDB.Interfaces;
using GdeWebModels;
using Microsoft.AspNetCore.Mvc;
using System.Net.Mime;

namespace GdeWebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AiController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        
        private readonly IAuthService _authService; // ha van ilyen szolgáltatásod

        private readonly ILogService _logService;

        private readonly AiService _ai;

        public AiController(IConfiguration configuration, IAuthService authService, ILogService logService, AiService ai)
        {
            this._configuration = configuration;
            this._authService = authService;
            this._logService = logService;
            this._ai = ai;
        }

        /// <summary>
        /// SSE stream GPT-től.
        /// </summary>
        [HttpPost("AiStream")]
        [ApiExplorerSettings(IgnoreApi = true)] // [ApiExplorerSettings(IgnoreApi = true)]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("text/event-stream")]
        public async Task AiStream([FromBody] MessageListModel model)
        {
            // (Ha kell user ellenőrzés:)
            // var userValid = await _authService.UserValidation(userId, userGuid);
            // if (!userValid.Success) { Response.ContentType = "text/event-stream"; await Response.WriteAsync("error:User invalid\n\n"); return; }

            Response.ContentType = "text/event-stream";
            Response.Headers["Cache-Control"] = "no-cache";
            Response.Headers["X-Accel-Buffering"] = "no";    // Nginx-hez
            HttpContext.RequestAborted.ThrowIfCancellationRequested();

            try
            {
                await foreach (var delta in _ai.StreamDeltasAsync(model, HttpContext.RequestAborted))
                {
                    var chunk = (delta ?? "").Replace("\n", "~$~"); // kompatibilitás a front olvasóddal
                    await Response.WriteAsync($"data:{chunk}\n\n");
                    await Response.Body.FlushAsync();
                }

                await Response.WriteAsync("success:ok\n\n");
                await Response.Body.FlushAsync();
            }
            catch (OperationCanceledException)
            {
                // kliens megszakította – semmi teendő
            }
            catch (Exception ex)
            {
                await Response.WriteAsync($"error:{ex.Message}\n\n");
                await Response.Body.FlushAsync();
            }
        }
    }
}
