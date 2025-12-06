using Blazored.LocalStorage;
using GdeWeb.Interfaces;
using GdeWebModels;
using Newtonsoft.Json;
using System.Data.Common;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection.Metadata;
using System.Text;
using System.Net.Http;
using System.Reflection;

namespace GdeWeb.Services
{
    public class UserService : IUserService
    {
        private readonly HttpClient httpClient;

        private readonly ILocalStorageService localStorageService;

        public UserService(HttpClient httpClient, ILocalStorageService localStorageService)
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



        public async Task<ResultModel> AddUser(UserModel model)
        {
            try
            {
                UserModel encryptedModel = new UserModel
                {
                    Email = model.Email,
                    Guid = model.Guid,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Password = Utilities.Utilities.EncryptPassword(model.Password),
                    Modifier = model.Modifier,
                    UserData = model.UserData,
                    Roles = model.Roles,
                    Result = new ResultModel() { Success = true, ErrorMessage = "" }
                };
                return await SendPostRequest<ResultModel>("api/User/AddUser", encryptedModel, false);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }


        public async Task<ResultModel> ForgotPassword(ForgotModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/ForgotPassword", model, false);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }



        // HITELESÍTÉSSEL



        public async Task<ResultModel> ModifyProfile(UserModel model)
        {
            try
            {
                UserModel encryptedModel = new UserModel
                {
                    Id = model.Id,
                    Guid = model.Guid,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Password = model.Password.Length == 0 ? "" : Utilities.Utilities.EncryptPassword(model.Password),
                    Modifier = model.Modifier,
                    Active = model.Active,
                    Roles = model.Roles,
                    Result = new ResultModel() { Success = true, ErrorMessage = "" }
                };
                return await SendPostRequest<ResultModel>("api/User/ModifyProfile", encryptedModel);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        // ModifyProfilePassword-nél, nincs hitelesítés, de rejtett az API láb
        public async Task<ProfilePasswordModel> ModifyProfilePassword(int userId, string password)
        {
            try
            {
                ProfilePasswordModel profilePasswordModel = new ProfilePasswordModel()
                {
                    UserId = userId,
                    ProfilePassword = Utilities.Utilities.EncryptPassword(password),
                    Modifier = userId,
                    Result = new ResultModel { Success = true, ErrorMessage = "" }
                };
                return await SendPostRequest<ProfilePasswordModel>("api/User/ModifyProfilePassword", profilePasswordModel);
            }
            catch (HttpRequestException ex)
            {
                return new ProfilePasswordModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }




        public async Task<UserListModel> GetUserList()
        {
            try
            {
                var result = await SendGetRequest<UserListModel>("api/User/GetUserList");
                if (result is not null && result?.UserList != null)
                {
                    // További műveletek a result változóval
                    foreach (UserModel user in result.UserList)
                    {
                        // Töröld az összes szerepkört, ahol a RoleId == 0
                        user.Roles = user.Roles.Where(role => role.Id != 0).ToList();
                    }
                }
                return result ?? new UserListModel() { Result = new ResultModel() { Success = false } };
            }
            catch (HttpRequestException ex)
            {
                return new UserListModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<ResultModel> ModifyUser(UserModel model)
        {
            try
            {
                UserModel encryptedModel = new UserModel
                {
                    Id = model.Id,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Password = string.IsNullOrEmpty(model.Password) ? "" : Utilities.Utilities.EncryptPassword(model.Password),
                    Modifier = model.Modifier,
                    Roles = model.Roles,
                    Result = new ResultModel() { Success = true, ErrorMessage = "" }
                };

                return await SendPostRequest<ResultModel>("api/User/ModifyUser", encryptedModel);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }


        public async Task<ResultModel> DeleteUser(UserModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/DeleteUser", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }


        public async Task<ResultModel> SetUserState(UserModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/SetUserState", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> SetUserData(LoginUserModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/SetUserData", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }



        public async Task<RoleListModel> GetRoles()
        {
            try
            {
                return await SendGetRequest<RoleListModel>("api/User/GetRoles");
            }
            catch (HttpRequestException ex)
            {
                return new RoleListModel { Result = new ResultModel { Success = false, ErrorMessage = ex.Message } };
            }
        }

        public async Task<ResultModel> AddRole(RoleModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/AddRole", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> ModifyRole(RoleModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/ModifyRole", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

        public async Task<ResultModel> DeleteRole(RoleModel model)
        {
            try
            {
                return await SendPostRequest<ResultModel>("api/User/DeleteRole", model);
            }
            catch (HttpRequestException ex)
            {
                return new ResultModel { Success = false, ErrorMessage = ex.Message };
            }
        }

    }
}