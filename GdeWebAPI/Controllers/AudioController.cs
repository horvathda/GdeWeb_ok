using Microsoft.AspNetCore.Mvc;
using GdeWebAPI.Controllers;
using GdeWebAPI.Middleware;
using GdeWebAPI.Utilities;
using GdeWebDB.Interfaces;
using GdeWebModels;
using tryAGI.OpenAI;

namespace GdeWebAPI.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class AudioController : ControllerBase
    {
        private readonly IAuthService _authService;

        private readonly IConfiguration _configuration;

        private readonly string _apiKey;

        public AudioController(IAuthService authService, IConfiguration configuration)
        {
            this._configuration = configuration;
            this._authService = authService;
            this._apiKey = _configuration["OpenAI:ApiKey"] ?? throw new InvalidOperationException("OpenAI ApiKey hiányzik (appsettings).");
        }

        [HttpPost("stt")]
        [ApiExplorerSettings(IgnoreApi = true)] // [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> Stt()
        {
            if (!HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
                return Unauthorized();

            var userId = Utilities.Utilities.GetUserIdFromToken(accessTokenHeader);
            var userGuid = Utilities.Utilities.GetUserGuidFromToken(accessTokenHeader);
            var userValid = await _authService.UserValidation(userId, userGuid);
            if (!userValid.Success) return Unauthorized();

            var file = Request.Form.Files[0];

            byte[] fileBytes;
            using (var memoryStream = new MemoryStream())
            {
                await file.CopyToAsync(memoryStream);
                fileBytes = memoryStream.ToArray();
            }

            //await System.IO.File.WriteAllBytesAsync(filePath, fileBytes);

            using var api = new OpenAiClient(_apiKey);

            CreateTranscriptionRequest requestTranscription = new CreateTranscriptionRequest()
            {
                File = fileBytes,
                Language = "hu",
                Filename = "audio.wav",
                Model = CreateTranscriptionRequestModel.Whisper1,
                ResponseFormat = AudioResponseFormat.Json,
                Temperature = 0,
            };

            CreateTranscriptionResponseJson responseTranscription = await api.Audio.CreateTranscriptionAsync(requestTranscription);

            return Ok(new { Text = responseTranscription.Text });
        }


        [HttpPost("tts")]
        [ApiExplorerSettings(IgnoreApi = true)] // [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> Tts([FromForm] string text)
        {
            if (!HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
                return Unauthorized();

            var userId = Utilities.Utilities.GetUserIdFromToken(accessTokenHeader);
            var userGuid = Utilities.Utilities.GetUserGuidFromToken(accessTokenHeader);
            var userValid = await _authService.UserValidation(userId, userGuid);
            if (!userValid.Success) return Unauthorized();

            using var api = new OpenAiClient(_apiKey);
            var req = new CreateSpeechRequest
            {
                Input = text,
                Voice = CreateSpeechRequestVoice.Nova,
                Speed = 1.0f,
                ResponseFormat = CreateSpeechRequestResponseFormat.Mp3,
                Model = CreateSpeechRequestModel.Tts1
            };

            var bytes = await api.Audio.CreateSpeechAsync(req); // várhatóan byte[]
            return File(bytes.ToArray(), "audio/mpeg");
        }
    }
}
