using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználó jelszó osztály")]
    public class ProfilePasswordModel
    {
        [SwaggerSchema("Felhasználó azonosítója")]
        public long UserId { get; set; } = 0;

        [SwaggerSchema("Felhasználó jelszava")]
        public string ProfilePassword { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó jelszavának modosítója")]
        public long Modifier { get; set; } = 0;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel();
    }
}