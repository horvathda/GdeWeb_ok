using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Login eredmény osztálya")]
    public class LoginResultModel
    {
        [SwaggerSchema("Login eredmény azonosítója")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Login eredmény engedély listája")]
        public List<LoginRoleModel> Roles { get; set; } = new List<LoginRoleModel> { new LoginRoleModel() };

        [SwaggerSchema("Login eredmény guid azonosítója")]
        public System.Guid Guid { get; set; } = Guid.NewGuid();

        [SwaggerSchema("Login eredmény token azonosítója")]
        public string Token { get; set; } = String.Empty;

        [SwaggerSchema("Login eredmény aktív")]
        public bool Active { get; set; } = false;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel();
    }
}
