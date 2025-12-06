using Azure;
using GdeWebDB;
using GdeWebDB.Entities;
using GdeWebDB.Interfaces;
using GdeWebDB.Services;
using GdeWebModels;
using HtmlAgilityPack;
using LangChain.Databases;
using LangChain.DocumentLoaders;
using LangChain.Extensions;
using LangChain.Providers;
using LangChain.Providers.OpenAI;
using LangChain.Providers.OpenAI.Predefined;
using MediaToolkit;
using MediaToolkit.Model;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using NAudio.Lame;
using NAudio.Wave;
using Newtonsoft.Json;
using System.Text;
using tryAGI.OpenAI;

namespace GdeWebAPI.Services
{
    /// <summary>
    /// Háttérben futó szolgáltatás (IHostedService/BackgroundService),
    /// amely időzített vagy folyamatos feladatokat végez az alkalmazás életciklusa alatt.
    /// </summary>
    public class HostedService : BackgroundService
    {
        private ILogger<HostedService> _logger;

        private readonly IConfiguration _configuration;

        private readonly IServiceScopeFactory _scopeFactory;

        private readonly AiService _ai;


        private string OpenAIApiKey = String.Empty;

        private static int count;

        private const long MaxWhisperMediaFileSize = 24 * 1024 * 1024; // 24 MB

        /// <summary>
        /// Létrehozza a <see cref="HostedService"/> példányt a szükséges függőségekkel.
        /// </summary>
        /// <param name="logger">Naplózó.</param>
        /// <param name="scopeFactory">Szolgáltatási scope gyár új scope-ok létrehozásához.</param>
        /// <param name="configuration">Alkalmazás konfiguráció.</param>
        public HostedService(ILogger<HostedService> logger, IServiceScopeFactory scopeFactory, IConfiguration configuration, AiService ai)
        {
            this._logger = logger;
            this._scopeFactory = scopeFactory;
            this._configuration = configuration;
            this._ai = ai;
        }

        /// <summary>
        /// A háttérfeladat fő ciklusa. A leállítást a <paramref name="stoppingToken"/> jelzi.
        /// </summary>
        /// <param name="stoppingToken">Leállítási kérés jelző token.</param>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                // Disabled loop
                Interlocked.Increment(ref count);
                _logger.LogInformation($"The count is {count} from Worker");

                // OpenAI Key
                OpenAIApiKey = _configuration["OpenAI:ApiKey"] ?? throw new ArgumentNullException();

                try
                {
                    using var scope = _scopeFactory.CreateScope();

                    // Scoped szolgáltatások felvétele scope-ból:
                    var _trainingService = scope.ServiceProvider.GetRequiredService<ITrainingService>();
                    var _logService = scope.ServiceProvider.GetRequiredService<ILogService>();

                    // TODO: a tényleges háttérmunka itt
                    CourseListModel courseListModel = await _trainingService.GetCourseGeneratingList();
                    if (courseListModel.Result.Success)
                    {
                        foreach (CourseModel course in courseListModel.CourseList.ToList())
                        {
                            // RUN COURSE GENERATING
                            #region RUN COURSE GENERATING
                            if (string.IsNullOrEmpty(course.CourseTitle) && !string.IsNullOrEmpty(course.CourseAiRequest.Topic))
                            {
                                // COURSE GENERATING
                                CourseAiResponseModel response = await RunCourseGenerating(_trainingService, _logService, course);

                                if (response is not null)
                                {
                                    // Mentés
                                    course.CourseTitle = response.title;
                                    course.CourseDescription = response.description;
                                    course.CourseFile = response.content;
                                    course.CourseAiResponse = response;
                                    course.ModificationDate = DateTime.Now;

                                    ResultModel result = await _trainingService.ModifyCourse(course);
                                    if (!result.Success)
                                    {
                                        await _logService.WriteMessageLogToFile($"Course generating hiba CourseId: {course.CourseId}, Error: {result.ErrorMessage}", "RunCourseGenerating");
                                    }
                                }
                            }
                            #endregion

                            // CREATE COURSE VECTOR DATABASE
                            #region CREATE COURSE VECTOR DATABASE
                            if (string.IsNullOrEmpty(course.CourseDB))
                            {
                                // COURSE GENERATING
                                await CreateCourseVectorDatabase(_trainingService, _logService, course);
                            }
                            #endregion

                            // AI KÉP GENERÁLÁS SCENE ALAPJÁN
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "HostedService cycle failed.");
                }

                // Enabled loop
                await Task.Delay(60 * 1000, stoppingToken); // Percenként fusson le
            }
        }

        /// <summary>
        /// RUN COURSE GENERATING
        /// </summary>
        #region RUN COURSE GENERATING
        private async Task<CourseAiResponseModel> RunCourseGenerating(ITrainingService _trainingService, ILogService _logService, CourseModel course)
        {
            CourseAiResponseModel dto = null;
            try
            {

                var userPrompt =
                $"Téma: {course.CourseAiRequest.Topic}, időtartam: {course.CourseAiRequest.Duration} másodperc, jelenetek: minimum {course.CourseAiRequest.MinScenes} darab, kérdések: {course.CourseAiRequest.QuizCount} darab, nyelv: {course.CourseAiRequest.Language}.";

                var messageList = new MessageListModel();
                messageList.GeneratePrompt = true;
                messageList.MessageList.Add(new MessageModel()
                {
                    Role = "user",
                    Message = userPrompt
                });

                var sb = new StringBuilder();
                await foreach (var delta in _ai.StreamDeltasAsync(messageList))
                {
                    sb.Append(delta);
                    // Itt tehetsz köztes feldolgozást is (log, mentés, SignalR broadcast, stb.)
                }

                var answer = sb.ToString();

                answer = answer.Replace("```json", String.Empty).Replace("```", String.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(answer))
                {
                    // --- JSON parse a AiGeneratedCourse-ba ---
                    try
                    {
                        dto = JsonConvert.DeserializeObject<CourseAiResponseModel>(answer);
                    }
                    catch
                    {
                        await _logService.WriteMessageLogToFile("A generált válasz nem érvényes JSON.", "CourseGenerating");
                    }

                    if (dto == null)
                    {
                        await _logService.WriteMessageLogToFile("A generált válasz feldolgozása sikertelen.", "CourseGenerating");
                    }
                }
                else
                {
                    await _logService.WriteMessageLogToFile("Üres válasz érkezett a generálásból.", "CourseGenerating");
                }

            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "RunCourseGenerating");
            }

            return dto;
        }
        #endregion


        /// <summary>
        /// CREATE COURSE VECTOR DATABASE
        /// </summary>
        #region CREATE COURSE VECTOR DATABASE
        private async Task CreateCourseVectorDatabase(ITrainingService _trainingService, ILogService _logService, CourseModel course)
        {
            try
            {
                bool change = false;

                // COURSE FILE
                if (!string.IsNullOrEmpty(course.CourseFile) && string.IsNullOrEmpty(course.CourseFileText))
                {
                    if (course.CourseFile.StartsWith("<"))
                    {
                        try
                        {
                            var doc = new HtmlDocument();
                            doc.LoadHtml(course.CourseFile);

                            // Kinyeri az összes látható szöveget
                            string plainText = doc.DocumentNode.InnerText;

                            // Eltávolítja a felesleges whitespace-eket, sortöréseket
                            course.CourseFileText = System.Net.WebUtility.HtmlDecode(plainText).Trim();

                            // Mentés
                            course.ModificationDate = DateTime.Now;
                            ResultModel result = await _trainingService.ModifyCourse(course);
                            if (!result.Success)
                            {
                                await _logService.WriteMessageLogToFile($"Course File hiba CourseId: {course.CourseId}, Error: {result.ErrorMessage}", "RunCourseGenerating");
                            }

                            change = true;
                        }
                        catch (Exception ex)
                        {
                            await _logService.WriteLogToFile(ex, "CreateCourseVectorDatabase");
                        }
                    }
                }

                // COURSE MEDIA
                if (!string.IsNullOrEmpty(course.CourseMedia) && string.IsNullOrEmpty(course.CourseMediaText))
                {
                    course = await ExtractTextFromMedia(_logService, course);

                    // Mentés
                    course.ModificationDate = DateTime.Now;
                    ResultModel result = await _trainingService.ModifyCourse(course);
                    if (!result.Success)
                    {
                        await _logService.WriteMessageLogToFile($"Course Media hiba CourseId: {course.CourseId}, Error: {result.ErrorMessage}", "RunCourseGenerating");
                    }

                    change = true;
                }

                // COURSE DB
                if ((change || string.IsNullOrEmpty(course.CourseDB)) && (!string.IsNullOrEmpty(course.CourseFileText) || !string.IsNullOrEmpty(course.CourseMediaText)))
                {
                    string vectorString = course.CourseFileText + "\n\n" + course.CourseMediaText;

                    // Course mappa ellenőrzése és létrehozása ha nem létezik
                    string vectorPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot", "vector");
                    if (!System.IO.Directory.Exists(vectorPath)) System.IO.Directory.CreateDirectory(vectorPath);

                    string fileName = "course" + course.CourseId + ".txt";
                    string filePath = $"{System.IO.Path.Combine(vectorPath, fileName)}";
                    System.IO.File.WriteAllText(filePath, vectorString);
                    string url = _configuration["apiUrl"] + "/vector/" + fileName;
                    string databasePath = Path.ChangeExtension(filePath, ".db");

                    // Vektor db-t készít
                    try
                    {
                        string collectionName = "data";

                        // INITIALIZE MODEL
                        var provider = new OpenAiProvider(OpenAIApiKey);
                        var embeddingModel = new TextEmbeddingV3SmallModel(provider);

                        // GENERATE VECTOR
                        using (var vectorDatabase = new LangChain.Databases.Sqlite.SqLiteVectorDatabase(dataSource: databasePath))
                        {
                            // A frissítéshez szükséges a régi adatokat törölni
                            if (await vectorDatabase.IsCollectionExistsAsync(collectionName))
                            {
                                await vectorDatabase.DeleteCollectionAsync(collectionName);
                            }

                            byte[] txtFileBytes = System.Text.Encoding.UTF8.GetBytes(vectorString);

                            // A törlés után létrehozzuk az új adatbázist
                            var vectorCollection = await vectorDatabase.AddDocumentsFromAsync<LangChain.DocumentLoaders.FileLoader>(
                                embeddingModel, // Used to convert text to embeddings
                                dimensions: 1536, // Should be 1536 for TextEmbeddingV3SmallModel
                                dataSource: DataSource.FromPath(filePath), // itt a file.Path helyett már az új fileName kell
                                collectionName: collectionName, // Can be omitted, use if you want to have multiple collections - FILE ID
                                textSplitter: null, // Default is CharacterTextSplitter(ChunkSize = 4000, ChunkOverlap = 200)
                                behavior: AddDocumentsToDatabaseBehavior.JustReturnCollectionIfCollectionIsAlreadyExists);

                            course.CourseDB = "/vector/" + "course" + course.CourseId + ".db";
                            course.ModificationDate = DateTime.Now;

                            // Mentés
                            ResultModel result = await _trainingService.ModifyCourse(course);
                            if (!result.Success)
                            {
                                await _logService.WriteMessageLogToFile($"Course DB hiba CourseId: {course.CourseId}, Error: {result.ErrorMessage}", "RunCourseGenerating");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        await _logService.WriteLogToFile(ex, "CreateCourseVectorDatabase");
                    }
                }
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "CreateCourseVectorDatabase");
            }
        }
        #endregion


        /// <summary>
        /// EXTRACT TEXT FROM MEDIA
        /// </summary>
        #region EXTRACT TEXT FROM MEDIA
        private async Task<CourseModel> ExtractTextFromMedia(ILogService _logService, CourseModel course)
        {
            try
            {
                // Média fájl darabolása 24Mb-os részekre
                List<string> mediaParts = await SplitMediaFileIntoParts(_logService, course);

                foreach (string mediaPart in mediaParts)
                {
                    byte[] mediaBytes = System.IO.File.ReadAllBytes(mediaPart);
                    //using var stream = System.IO.File.OpenRead(mediaPart); // helyes fájl stream

                    // ChatGPT
                    using var api = new OpenAiClient(OpenAIApiKey);

                    // Request
                    CreateTranscriptionRequest requestTranscription = new CreateTranscriptionRequest()
                    {
                        File = mediaBytes, // stream
                        Language = "hu",
                        Filename = "audio.mp3",
                        Model = CreateTranscriptionRequestModel.Whisper1,
                        ResponseFormat = AudioResponseFormat.Json,
                        Temperature = 0,
                    };

                    CreateTranscriptionResponseJson responseTranscription = await api.Audio.CreateTranscriptionAsync(requestTranscription);

                    if (responseTranscription is not null)
                    {
                        course.CourseMediaText += responseTranscription.Text + "\n";
                    }
                }

                // TÖRÖLJÜK AZ IDEIGLENES FÁJLOKAT
                foreach (string mediaPart in mediaParts)
                {
                    if (System.IO.File.Exists(mediaPart))
                    {
                        System.IO.File.Delete(mediaPart);
                    }
                }

                return course;
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "ExtractTextFromMedia");

                course.Result = new ResultModel() { Success = false, ErrorMessage = $"Hiba a feldolgozás közben: {ex.Message.ToString()}" };

                return course;
            }
        }
        #endregion


        /// <summary>
        /// SPLIT MEDIA FILE INTO PARTS
        /// </summary>
        #region SPLIT MEDIA FILE INTO PARTS
        private async Task<List<string>> SplitMediaFileIntoParts(ILogService _logService, CourseModel course)
        {
            List<string> parts = new List<string>();
            string filePath = Utilities.Utilities.GetPath(course.CourseMedia);
            FileInfo file = new FileInfo(filePath);
            byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);

            var provider = new FileExtensionContentTypeProvider();
            if (provider.TryGetContentType(file.FullName, out string contentType))
            {
                try
                {
                    if (contentType.Contains("audio/mpeg") && file.Length < MaxWhisperMediaFileSize)
                    {
                        // Copy backup
                        string outputFileName = filePath.Replace(".mp3", $"_0.mp3");
                        System.IO.File.Copy(filePath, outputFileName, true);

                        parts.Add(outputFileName);

                        return parts;
                    }

                    // CONVERT TO WAV
                    string tempWavFile = "";
                    if (contentType.Contains("video/mp4") || contentType.Contains("audio/mpeg"))
                    {
                        // Convert MP4 or MPEG to WAV using MediaToolkit
                        tempWavFile = System.IO.Path.ChangeExtension(filePath, ".wav");
                        var inputFileMedia = new MediaFile { Filename = filePath };
                        var outputFileMedia = new MediaFile { Filename = tempWavFile };

                        using (var engine = new Engine())
                        {
                            engine.GetMetadata(inputFileMedia);
                            engine.Convert(inputFileMedia, outputFileMedia);
                        }
                    }

                    // WAV SPLIT AND SAVE MP3
                    if (!string.IsNullOrEmpty(tempWavFile) && System.IO.File.Exists(tempWavFile))
                    {
                        // Create a WaveStream from the input WAV file
                        using (var reader = new WaveFileReader(tempWavFile))
                        {
                            int index = 0;

                            while (reader.Position < reader.Length)
                            {
                                // Create a WaveFileWriter for each chunk
                                string outputFileName = tempWavFile.Replace(".wav", $"_{index}.mp3");
                                using (var writer = new LameMP3FileWriter(outputFileName, reader.WaveFormat, LAMEPreset.STANDARD))
                                {
                                    long bytesToRead = MaxWhisperMediaFileSize;
                                    while (bytesToRead > 0 && reader.Position < reader.Length)
                                    {
                                        int bytesToCopy = (int)Math.Min(bytesToRead, reader.Length - reader.Position);
                                        byte[] buffer = new byte[bytesToCopy];
                                        int bytesRead = reader.Read(buffer, 0, bytesToCopy);
                                        writer.Write(buffer, 0, bytesRead);
                                        bytesToRead -= bytesRead;
                                    }
                                }
                                index++;
                                parts.Add(outputFileName);
                            }
                        }
                    }

                    // TEMP FILE REMOVE
                    if (System.IO.File.Exists(tempWavFile))
                    {
                        System.IO.File.Delete(tempWavFile);
                    }

                    return parts;
                }
                catch (Exception ex)
                {
                    await _logService.WriteLogToFile(ex, "SplitMediaFileIntoParts");

                    return parts;
                }
            }
            else
            {
                // Ismeretlen fájlkiterjesztés
                return parts;
            }
        }
        #endregion
    }
}
