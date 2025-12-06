using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Login token osztálya")]
    public class LoginTokenModel
    {
        [SwaggerSchema("Login token azonosítója")]
        public string Token { get; set; } = String.Empty;
    }
}