using Swashbuckle.AspNetCore.Annotations;
using System.Collections.Generic;

namespace GdeWebModels
{
    [SwaggerSchema("Szerepkörök lista osztálya")]
    public class RoleListModel
    {
        [SwaggerSchema("Szerepkörök listája")]
        public List<RoleModel> RoleList { get; set; } = new List<RoleModel>();

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}