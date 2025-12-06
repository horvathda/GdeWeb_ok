using GdeWebAPI.Middleware;
using GdeWebDB.Interfaces;
using GdeWebModels;
using LangChain.Providers;
using LangChain.Providers.OpenAI;
using LangChain.Providers.OpenAI.Predefined;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Swashbuckle.AspNetCore.Annotations;
using System.Net.Mime;
using System.Reflection.Metadata;

namespace GdeWebAPI.Controllers
{
    /// <summary>
    /// Képzések, kurzusok és kvízek kezeléséért felelős API vezérlő.
    /// Lehetővé teszi kurzusok létrehozását, módosítását, törlését és a hozzájuk tartozó kvízek kezelését.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [DisableRateLimiting]
    public class TrainingController : ControllerBase
    {
        private readonly ITrainingService _trainingService;
        private readonly IAuthService _authService;          // ha jogosultság-ellenőrzést szeretnél
        private readonly ILogService _logService;
        private readonly IConfiguration _configuration;

        private readonly string wwwrootPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot");

        /// <summary>
        /// Létrehozza a <see cref="TrainingController"/> példányt a szükséges szolgáltatásokkal.
        /// </summary>
        /// <param name="trainingService">Képzési műveletekért felelős szolgáltatás.</param>
        /// <param name="authService">Felhasználók és tokenek hitelesítését végzi.</param>
        /// <param name="logService">Naplózási műveletek szolgáltatója.</param>
        /// <param name="configuration">Alkalmazás konfigurációs beállításai.</param>
        public TrainingController(ITrainingService trainingService, IAuthService authService, ILogService logService, IConfiguration configuration)
        {
            _trainingService = trainingService;
            _authService = authService;
            _logService = logService;
            _configuration = configuration;
        }

        // -------- COURSE --------

        /// <summary>
        /// Visszaadja a kurzus részletes adatait.
        /// </summary>
        /// <param name="model">A lekérni kívánt kurzus azonosítója.</param>
        /// <returns>A kurzus adatai.</returns>
        [HttpPost]
        [Route("GetCourse")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Egy kurzus lekérdezése", Description = "CourseModel = GetCourse(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<CourseModel> GetCourse(CourseModel model)
        {
            return await _trainingService.GetCourse(model);
        }

        /// <summary>
        /// Visszaadja az összes elérhető kurzust.
        /// </summary>
        /// <returns>A kurzusok listája.</returns>
        [HttpGet]
        [Route("GetCourseList")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kurzusok listája", Description = "CourseListModel = GetCourseList()")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<CourseListModel> GetCourseList()
        {
            return await _trainingService.GetCourseList();
        }

        /// <summary>
        /// Új kurzust hoz létre.
        /// </summary>
        /// <param name="model">A kurzus adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("AddCourse")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kurzus létrehozása", Description = "ResultModel = AddCourse(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> AddCourse([FromBody] CourseModel model)
        {
            return await _trainingService.AddCourse(model);
        }

        /// <summary>
        /// Meglévő kurzus adatainak módosítása.
        /// </summary>
        /// <param name="model">A módosított kurzus adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("ModifyCourse")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kurzus módosítása", Description = "ResultModel = ModifyCourse(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> ModifyCourse([FromBody] CourseModel model)
        {
            return await _trainingService.ModifyCourse(model);
        }

        /// <summary>
        /// Törli a megadott kurzust.
        /// </summary>
        /// <param name="model">A törlendő kurzus azonosítója.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("DeleteCourse")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kurzus törlése", Description = "ResultModel = DeleteCourse(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> DeleteCourse([FromBody] CourseModel model)
        {
            if (model == null || model.CourseId <= 0)
                return new ResultModel { Success = false, ErrorMessage = "Érvénytelen CourseId." };

            // Eltávolítja a médiaelem fájljait
            if (!string.IsNullOrEmpty(model.CourseMedia) && !model.CourseMedia.StartsWith("data:"))
            {
                string fullFilePath = Path.Combine(wwwrootPath, model.CourseMedia.TrimStart('/').Replace('/', '\\'));
                if (System.IO.File.Exists(fullFilePath))
                {
                    System.IO.File.Delete(fullFilePath);
                }
            }

            if (!string.IsNullOrEmpty(model.CourseDB))
            {
                // Lecseréli a vector .db-t
                string dbFilePath = Path.Combine(wwwrootPath, model.CourseDB.TrimStart('/').Replace('/', '\\'));
                if (System.IO.File.Exists(dbFilePath))
                {
                    System.IO.File.Delete(dbFilePath);
                }
            }

            return await _trainingService.DeleteCourse(model);
        }

        // -------- QUIZ --------

        /// <summary>
        /// Visszaadja az összes kvíz kérdést.
        /// </summary>
        /// <returns>A kvízek listája.</returns>
        [HttpGet]
        [Route("GetQuizList")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Összes kvíz lekérdezése", Description = "QuizListModel = GetQuizList()")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<QuizListModel> GetQuizList()
        {
            return await _trainingService.GetQuizList();
        }

        /// <summary>
        /// Visszaadja a kurzushoz tartozó kvízeket.
        /// </summary>
        /// <param name="model">A kurzus azonosítója.</param>
        /// <returns>A kvízek listája.</returns>
        [HttpPost]
        [Route("GetCourseQuizzes")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Egy kurzus kvízei", Description = "QuizListModel = GetCourseQuizzes(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<QuizListModel> GetCourseQuizzes([FromBody] CourseModel model)
        {
            return await _trainingService.GetCourseQuizzes(model);
        }

        /// <summary>
        /// Új kvízt ad a kurzushoz.
        /// </summary>
        /// <param name="model">A kvíz adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("AddQuiz")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kvíz létrehozása", Description = "ResultModel = AddQuiz(QuizModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> AddQuiz([FromBody] QuizModel model)
        {
            return await _trainingService.AddQuiz(model);
        }

        /// <summary>
        /// Meglévő kvíz adatainak módosítása.
        /// </summary>
        /// <param name="model">A módosított kvíz adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("ModifyQuiz")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kvíz módosítása", Description = "ResultModel = ModifyQuiz(QuizModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> ModifyQuiz([FromBody] QuizModel model)
        {
            return await _trainingService.ModifyQuiz(model);
        }

        /// <summary>
        /// Törli a megadott kurzus összes kvíz kérdését.
        /// </summary>
        /// <param name="model">A kurzus azonosítója.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("RemoveCourseQuizzes")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Kurzus összes kvízének törlése", Description = "ResultModel = RemoveCourseQuizzes(CourseModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> RemoveCourseQuizzes([FromBody] CourseModel model)
        {
            if (model == null || model.CourseId <= 0)
                return new ResultModel { Success = false, ErrorMessage = "Érvénytelen CourseId." };

            return await _trainingService.RemoveCourseQuizzes(model);
        }

        /// <summary>
        /// Törli a megadott kvízt.
        /// </summary>
        /// <param name="model">A törlendő kvíz azonosítója.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("RemoveQuiz")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(Summary = "Egy kvíz törlése", Description = "ResultModel = RemoveQuiz(QuizModel model)")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> RemoveQuiz([FromBody] QuizModel model)
        {
            if (model == null || model.QuizId <= 0)
                return new ResultModel { Success = false, ErrorMessage = "Érvénytelen QuizId." };

            return await _trainingService.RemoveQuiz(model);
        }


        // -------- HTML --------

        /// <summary>
        /// Kurzus HTML leírásának kép részleteit tölti fel (chunkolva).
        /// </summary>
        /// <param name="model">A HTML chunk adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("UploadHtmlImageChunk")]
        [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "HTML beágyazott kép feltöltése",
            Description = "ResultModel = UploadHtmlImageChunk(HtmlImageModel model) -> wwwroot/html/"
        )]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> UploadHtmlImageChunk(HtmlImageModel model)
        {
            if (!HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };

            string accessToken = accessTokenHeader.ToString();

            int userId = Utilities.Utilities.GetUserIdFromToken(accessToken);
            string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessToken);

            if (string.IsNullOrEmpty(userId.ToString()) || string.IsNullOrEmpty(userGuid))
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };

            ResultModel userValid = await _authService.UserValidation(userId, userGuid);
            if (!userValid.Success)
                return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };

            // --- VALIDÁCIÓ ---
            if (model.Data == null || model.Data.Length == 0)
                return new ResultModel() { Success = false, ErrorMessage = "File is empty!" };

            var extension = Path.GetExtension(model.Name);
            var safeName = new Guid().ToString() + extension;
            if (string.IsNullOrWhiteSpace(safeName))
                return new ResultModel() { Success = false, ErrorMessage = "Invalid filename!" };

            // --- KÖNYVTÁR ---
            string basePath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot", "html");
            if (!System.IO.Directory.Exists(basePath)) System.IO.Directory.CreateDirectory(basePath);

            // --- MENTÉS ---
            string filePath = Path.Combine(basePath, safeName);
            string relativeUrl = Path.Combine("html", safeName).Replace("\\", "/");

            try
            {
                long offset = model.Size; // 0 új fájl, >0 append
                using (var stream = new FileStream(filePath, offset == 0 ? FileMode.Create : FileMode.Append))
                {
                    await stream.WriteAsync(model.Data, 0, model.Data.Length);
                }
            }
            catch (Exception ex)
            {
                return new ResultModel() { Success = false, ErrorMessage = ex.Message };
            }

            return new ResultModel() { Success = true, ErrorMessage = relativeUrl };
        }



        // -------- VIDEO --------

        /// <summary>
        /// Kurzus Videó tartalmát tölti fel (chunkolva).
        /// </summary>
        /// <param name="model">A videó chunk adatai.</param>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpPost]
        [Route("UploadTrainingFileChunk")]
        [ApiExplorerSettings(IgnoreApi = true)] // [ApiExplorerSettings(IgnoreApi = true)]
        [SwaggerOperation(
            Summary = "Feltölt egy fájlt",
            Description = "ResultModel = UploadTrainingFileChunk(AgiliTrainingFileModel model)"
        )]
        [Consumes(MediaTypeNames.Application.Json)] // "application/json"
        [Produces("application/json")]
        [ServiceFilter(typeof(AccessTokenFilter))]
        public async Task<ResultModel> UploadTrainingFileChunk(TrainingFileModel model)
        {
            // Ellenőrizzük, hogy létezik-e a "AccessToken" header
            if (HttpContext.Request.Headers.TryGetValue("AccessToken", out var accessTokenHeader))
            {
                int userId = Utilities.Utilities.GetUserIdFromToken(accessTokenHeader);
                string userGuid = Utilities.Utilities.GetUserGuidFromToken(accessTokenHeader);

                if (!string.IsNullOrEmpty(userId.ToString()) && !string.IsNullOrEmpty(userGuid))
                {
                    ResultModel userValid = await _authService.UserValidation(userId, userGuid);

                    if (userValid.Success)
                    {
                        // AccessToken érvényes, folytathatja a kérést

                        if (model.Data == null || model.Data.Length == 0)
                        {
                            return new ResultModel() { Success = false, ErrorMessage = "File is empty!" };
                        }

                        // Media mappa ellenőrzése és létrehozása ha nem létezik
                        string mediaPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot", "media");
                        if (!System.IO.Directory.Exists(mediaPath)) System.IO.Directory.CreateDirectory(mediaPath);

                        // Fájl mentése a mappába
                        #region Fájl mentése a mappába
                        string filePath = $"{System.IO.Path.Combine(mediaPath, model.Name)}";

                        string Url = "media/" + model.Name;

                        // Ha az offset 0, akkor új fájl, különben folytatódik a feltöltés
                        long offset = model.Size;
                        try
                        {
                            using (var stream = new FileStream(filePath, offset == 0 ? FileMode.Create : FileMode.Append))
                            {
                                //await file.CopyToAsync(stream);
                                await stream.WriteAsync(model.Data, 0, model.Data.Length);
                            }
                        }
                        catch (Exception ex)
                        {
                            return new ResultModel() { Success = false, ErrorMessage = ex.Message.ToString() };
                        }
                        #endregion

                        return new ResultModel() { Success = true, ErrorMessage = Url };
                    }
                    else
                    {
                        return new ResultModel() { Success = false, ErrorMessage = "User is not valid!" };
                    }
                }
                else
                {
                    return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
                }
            }
            else
            {
                return new ResultModel() { Success = false, ErrorMessage = "Forbidden: Invalid or missing AccessToken." };
            }
        }


        // -------- DOWNLOAD APK --------

        /// <summary>
        /// Mobil applikáció letöltése.
        /// </summary>
        /// <returns>Siker vagy hiba státusza.</returns>
        [HttpGet]
        [Route("DownloadAndroid")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult DownloadApk()
        {
            string filePath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot", "update", "gdeweb.app.signed.apk");

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("The file was not found on the server.");
            }

            var fileBytes = System.IO.File.ReadAllBytes(filePath);
            return File(fileBytes, "application/vnd.android.package-archive", "gdeweb.app.signed.apk");
        }
    }
}

