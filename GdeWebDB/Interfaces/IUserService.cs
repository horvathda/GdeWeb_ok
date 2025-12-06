using GdeWebModels;

namespace GdeWebDB.Interfaces
{
    public interface IUserService
    {



        // HITELESÍTÉS NÉLKÜL



        Task<UserModel> GetUser(int userId);

        Task<RoleModel> GetRole(int roleId);



        // HITELESÍTÉSSEL



        Task<ResultModel> ModifyProfile(UserModel parameter);

        Task<ProfilePasswordModel> ModifyProfilePassword(ProfilePasswordModel parameter);



        Task<UserListModel> GetUserList();

        Task<ResultModel> AddUser(UserModel parameter);

        Task<ResultModel> ModifyUser(UserModel parameter);

        Task<ResultModel> DeleteUser(UserModel parameter);

        Task<ResultModel> SetUserState(UserModel parameter);

        Task<ResultModel> SetUserData(LoginUserModel parameter);



        Task<RoleListModel> GetRoles();

        Task<ResultModel> AddRole(RoleModel parameter);

        Task<ResultModel> ModifyRole(RoleModel parameter);

        Task<ResultModel> DeleteRole(RoleModel parameter);
    }
}