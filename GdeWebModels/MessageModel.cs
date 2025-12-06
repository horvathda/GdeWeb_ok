using Newtonsoft.Json;
using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Üzenet osztálya")]
    public class MessageModel
    {
        [SwaggerSchema("Üzenet azonosítója")]
        public int Id { get; set; } = 0;

        [SwaggerSchema("Üzenet küldője")]
        public string Role { get; set; } = String.Empty;

        [SwaggerSchema("Üzenet szövege")]
        public string Message { get; set; } = String.Empty;

        [SwaggerSchema("Üzenet küldõjének IP címe")]
        public string? IPAddress { get; set; } = String.Empty;

        [SwaggerSchema("Üzenet küldésének dátuma")]
        public DateTime Date { get; set; } = DateTime.Now;
    }
}
