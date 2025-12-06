using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Elfelejtett jelszó osztálya")]
    public class ForgotModel
    {
        [SwaggerSchema("Email címzettjének email címe")]
        public string Email { get; set; } = String.Empty;
    }
}