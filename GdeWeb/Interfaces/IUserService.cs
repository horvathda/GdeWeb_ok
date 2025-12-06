using GdeWebModels;

namespace GdeWeb.Interfaces
{
    public interface IUserService
    {



        // HITELESÍTÉS NÉLKÜL



        Task<ResultModel> AddUser(UserModel model);

        Task<ResultModel> ForgotPassword(ForgotModel model);



        // HITELESÍTÉSSEL



        Task<ResultModel> ModifyProfile(UserModel model);

        Task<ProfilePasswordModel> ModifyProfilePassword(int userId, string password);



        Task<UserListModel> GetUserList();

        Task<ResultModel> ModifyUser(UserModel model);

        Task<ResultModel> DeleteUser(UserModel model);

        Task<ResultModel> SetUserState(UserModel model);

        Task<ResultModel> SetUserData(LoginUserModel model);



        Task<RoleListModel> GetRoles();

        Task<ResultModel> AddRole(RoleModel model);

        Task<ResultModel> ModifyRole(RoleModel model);

        Task<ResultModel> DeleteRole(RoleModel model);

    }
}