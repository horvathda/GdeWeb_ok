using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Email osztálya")]
    public class EmailModel
    {
        [SwaggerSchema("Email azonosítója")]
        public long Id { get; set; } = 0;

        [SwaggerSchema("Email címzettjének email címe")]
        public string ToEmail { get; set; } = String.Empty;

        [SwaggerSchema("Email küldőjének neve")]
        public string Name { get; set; } = String.Empty;

        [SwaggerSchema("Email küldőjének telefonszáma")]
        public string Phone { get; set; } = String.Empty;

        [SwaggerSchema("Email küldőjének email címe")]
        public string FromEmail { get; set; } = String.Empty;

        [SwaggerSchema("Email tárgy")]
        public string Subject { get; set; } = String.Empty;

        [SwaggerSchema("Email üzenet")]
        public string Message { get; set; } = String.Empty;

        [SwaggerSchema("Létrehozás dátuma")]
        public DateTime CreatingDate { get; set; } = new DateTime();

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel();
    }
}