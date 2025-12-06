using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Login szerepkör osztálya")]
    public class LoginRoleModel
    {
        [SwaggerSchema("Login szerepkör azonosítója")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Login szerepkör neve")]
        public string Name { get; set; } = String.Empty;
    }
}