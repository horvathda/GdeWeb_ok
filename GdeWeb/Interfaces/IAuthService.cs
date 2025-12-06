using GdeWebModels;

namespace GdeWeb.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResultModel> Login(LoginModel credential);

        Task<LoginUserModel> GetUserFromToken(LoginTokenModel credential);
    }
}
