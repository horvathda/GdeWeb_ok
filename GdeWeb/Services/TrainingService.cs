using Blazored.LocalStorage;
using GdeWeb.Interfaces;
using GdeWebModels;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;

namespace GdeWeb.Services
{
    public class TrainingService : ITrainingService
    {
        private readonly HttpClient httpClient;
        private readonly ILocalStorageService localStorageService;

        public TrainingService(HttpClient httpClient, ILocalStorageService localStorageService)
        {
            this.httpClient = httpClient;
            this.localStorageService = localStorageService;
        }

        // -------------- Helpers --------------

        private async Task<T> SendGetRequest<T>(string endpoint, bool requireAuth = true)
        {
            HttpRequestMessage request;
            if (requireAuth)
            {
                var accessToken = await localStorageService.GetItemAsync<string>("token");
                if (accessToken == null)
                    throw new HttpRequestException("Hiba történt: Token nem található!");

                request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Add("AccessToken", accessToken);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }
            else
            {
                request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }

            var response = await httpClient.SendAsync(request);
            return await HandleResponse<T>(response);
        }


        private async Task<T> SendPostRequest<T>(string endpoint, object data, bool requireAuth = true)
        {
            HttpRequestMessage request;
            if (requireAuth)
            {
                var accessToken = await localStorageService.GetItemAsync<string>("token");
                if (accessToken == null)
                    throw new HttpRequestException("Hiba történt: Token nem található!");

                var jsonString = JsonConvert.SerializeObject(data);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
                request.Headers.Add("AccessToken", accessToken);
            }
            else
            {
                var jsonString = JsonConvert.SerializeObject(data);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
            }

            var response = await httpClient.SendAsync(request);
            return await HandleResponse<T>(response);
        }


        private async Task<T> HandleResponse<T>(HttpResponseMessage response)
        {
            if (response is null)
                throw new HttpRequestException("Üres válasz érkezett a szervertől.");

            var jsonResponse = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Hiba történt: {response.StatusCode}, Üzenet: {jsonResponse}");

            var result = JsonConvert.DeserializeObject<T>(jsonResponse);

            if (result is null)
                throw new JsonException("A szerver válasza érvénytelen vagy üres JSON volt.");

            return result;
        }

        // -------------- COURSE --------------

        public async Task<CourseModel> GetCourse(CourseModel model)
        {
            try
            {
                return await SendPostRequest<CourseModel>($"api/Training/GetCourse", model);
            }
            catch (HttpRequestException ex)
            {
                return new CourseModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<CourseListModel> GetCourseList()
        {
            try
            {
                return await SendGetRequest<CourseListModel>("api/Training/GetCourseList");
            }
            catch (HttpRequestException ex)
            {
                return new CourseListModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<ResultModel> AddCourse(CourseModel model)
        {
            try
            {
                // nincs extra kliens oldali átalakítás
                return await SendPostRequest<ResultModel>("api/Training/AddCourse", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> ModifyCourse(CourseModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/ModifyCourse", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> DeleteCourse(CourseModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/DeleteCourse", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        // -------------- QUIZ --------------

        public async Task<QuizListModel> GetQuizList()
        {
            try
            {
                return await SendGetRequest<QuizListModel>("api/Training/GetQuizList");
            }
            catch (HttpRequestException ex)
            {
                return new QuizListModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<QuizListModel> GetCourseQuizzes(CourseModel model)
        {
            try
            {
                return await SendPostRequest<QuizListModel>($"api/Training/GetCourseQuizzes", model);
            }
            catch (HttpRequestException ex)
            {
                return new QuizListModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<ResultModel> AddQuiz(QuizModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/AddQuiz", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> ModifyQuiz(QuizModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/ModifyQuiz", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> RemoveCourseQuizzes(CourseModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/RemoveCourseQuizzes", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> RemoveQuiz(QuizModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/RemoveQuiz", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }


        // -------------- HTML --------------

        public async Task<ResultModel> UploadHtmlImageChunk(HtmlImageModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/Training/UploadHtmlImageChunk", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel() { Success = false, ErrorMessage = ex.Message };
            }
        }


        // -------------- VIDEO --------------

        public async Task<ResultModel> UploadTrainingFileChunk(byte[] chunk, long offset, string fileName)
        {
            try
            {
                // Adat előkészítése
                TrainingFileModel model = new TrainingFileModel()
                {
                    Data = chunk,
                    Size = offset,
                    Name = fileName
                };

                return await SendPostRequest<ResultModel>("api/Training/UploadTrainingFileChunk", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel() { Success = false, ErrorMessage = ex.Message };
            }
        }
    }
}

