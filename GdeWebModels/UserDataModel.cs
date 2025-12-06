using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználói adatok osztálya")]
    public class UserDataModel
    {
        [SwaggerSchema("Felhasználó neme")]
        public string Sex { get; set; } = String.Empty;

        [SwaggerSchema("Felhasználó születési ideje")]
        public DateTime? Birthday { get; set; } = new DateTime(1900, 1, 1);

        [SwaggerSchema("Megtekintett kurzusok")]
        public List<UserEventModel> Courses { get; set; } = new List<UserEventModel>();

        [SwaggerSchema("Megszerzett jelvények")]
        public List<UserEventModel> Badges { get; set; } = new List<UserEventModel>();

        [SwaggerSchema("Kvízek eredményei")]
        public List<UserQuizModel> Quizzes { get; set; } = new List<UserQuizModel>();

        [SwaggerSchema("Utolsó belépés dátuma")]
        public DateTime LastLoginDate { get; set; } = DateTime.Now;
    }
}