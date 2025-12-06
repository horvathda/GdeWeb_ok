using Newtonsoft.Json;
using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Login felhasználó osztálya")]
    public class LoginUserModel
    {
        [SwaggerSchema("Login felhasználó azonosítója")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Login felhasználó guid azonosítója")]
        public System.Guid Guid { get; set; } = Guid.NewGuid();

        [SwaggerSchema("Login token azonosítója")]
        public string Token { get; set; } = String.Empty;

        [SwaggerSchema("Login felhasználó keresztneve")]
        public string FirstName { get; set; } = String.Empty;

        [SwaggerSchema("Login felhasználó vezetékneve")]
        public string LastName { get; set; } = String.Empty;

        [SwaggerSchema("Login felhasználó email címe")]
        public string Email { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó személyes adatai")]
        public UserDataModel UserData { get; set; } = new UserDataModel();

        [SwaggerSchema("Login felhasználó szerepkör listája")]
        public List<LoginRoleModel> Roles { get; set; } = new List<LoginRoleModel> { new LoginRoleModel() };

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel();


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