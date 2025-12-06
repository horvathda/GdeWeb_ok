using Blazored.LocalStorage;
using Newtonsoft.Json;
using GdeWeb.Interfaces;
using GdeWebModels;
using System.Net.Http.Headers;
using System.Text;

namespace GdeWeb.Services
{
    public class AuthService: IAuthService
    {
        private readonly HttpClient httpClient;

        private readonly ILocalStorageService localStorageService;

        public AuthService(HttpClient httpClient, ILocalStorageService localStorageService)
        {
            this.httpClient = httpClient;
            this.localStorageService = localStorageService;
        }




        // FUNCTIONS




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




        // HITELESÍTÉS NÉLKÜL




        public async Task<LoginResultModel> Login(LoginModel credential)
        {
            try
            {
                // Itt nincs jelszó titkosítás, hogy a tokent le tudják kérdezni!!  (Előre nem tudják, hogy miként van hitelesítve)
                // SHA-512
                LoginModel encryptedCredentials = new LoginModel { Email = credential.Email, Password = Utilities.Utilities.EncryptPassword(credential.Password) };

                return await SendPostRequest<LoginResultModel>("api/Auth/Login", encryptedCredentials, false);
            }
            catch (HttpRequestException ex)
            {
                return new LoginResultModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<LoginUserModel> GetUserFromToken(LoginTokenModel credential)
        {
            try
            {
                return await SendPostRequest<LoginUserModel>("api/Auth/GetUserFromToken", credential, false);
            }
            catch (HttpRequestException ex)
            {
                if (ex.Message.Contains("Unauthenticated"))
                {
                    return new LoginUserModel { Result = new ResultModel { Success = false, ErrorMessage = "401" } };
                }
                return new LoginUserModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }
    }
}
