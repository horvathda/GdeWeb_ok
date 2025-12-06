using GdeWebModels;
using Newtonsoft.Json;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználó osztály")]
    public class UserModel
    {
        [SwaggerSchema("Felhasználó azonosító")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Login felhasználó guid azonosítója")]
        public object Guid { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó jelszava")]
        public string Password { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó keresztneve")]
        public string FirstName { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó vezetékneve")]
        public string LastName { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó email címe")]
        public string Email { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó személyes adatai")]
        public UserDataModel UserData { get; set; } = new UserDataModel();

        [SwaggerSchema("Felhasználó aktív")]
        public bool Active { get; set; } = false;

        [SwaggerSchema("Felhasználó módosítója")]
        public int Modifier { get; set; } = 0;

        [SwaggerSchema("Felhasználó szerepköreinek listája")]
        public List<RoleModel> Roles { get; set; } = new List<RoleModel> { new RoleModel() };

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };


        [SwaggerSchema("Felhasználó személyes adatainak json string formátuma")]
        // Property to hold the JSON string in the database
        [Newtonsoft.Json.JsonIgnore] // Ezt add hozzá
        public string UserDataJson
        {
            get => String.Empty;
            set
            {
                UserData = string.IsNullOrEmpty(value) 
                    ? new UserDataModel() 
                    : JsonConvert.DeserializeObject<UserDataModel>(value) ?? new UserDataModel();
            }
        }
    }
}