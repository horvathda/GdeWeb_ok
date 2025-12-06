using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;

namespace GdeWebModels
{
    [SwaggerSchema("Szerepkör osztály")]
    public class RoleModel
    {
        [SwaggerSchema("Szerepkör azonosítója")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Szerepkör felhasználó azonosítója")]
        public int UserId { get; set; } = 0;

        [SwaggerSchema("Szerepkör neve")]
        public string Name { get; set; } = String.Empty;

        [SwaggerSchema("Szerepkör részletek megjelenítése")]
        public bool ShowDetails { get; set; } = false;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}