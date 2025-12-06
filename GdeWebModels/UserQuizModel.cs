using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználó kvíz osztálya")]
    public class UserQuizModel
    {
        [SwaggerSchema("Kvíz kurzus azonosítója")]
        public int CourseId { get; set; } = 0;

        [SwaggerSchema("Kvíz kérdések száma")]
        public int QuizQuestion { get; set; } = 0;

        [SwaggerSchema("Kvíz kérdések sikeres eredménye")]
        public int QuizResult { get; set; } = 0;

        [SwaggerSchema("Kvíz napi küldetés")]
        public bool DailyQuiz { get; set; } = false;

        [SwaggerSchema("Módosítás dátuma")]
        public DateTime ModificationDate { get; set; } = DateTime.Now;
    }
}
