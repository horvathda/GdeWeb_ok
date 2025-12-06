using Swashbuckle.AspNetCore.Annotations;
using System.Collections.Generic;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználók lista osztálya")]
    public class UserListModel
    {
        [SwaggerSchema("Felhasználók listája")]
        public List<UserModel> UserList { get; set; } = new List<UserModel>();

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}