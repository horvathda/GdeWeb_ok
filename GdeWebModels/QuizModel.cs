using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Kvíz osztálya")]
    public class QuizModel
    {
        [SwaggerSchema("Kvíz azonosítója")]
        public int QuizId { get; set; } = 0;

        [SwaggerSchema("Kurzus azonosítója")]
        public int CourseId { get; set; } = 0;

        [SwaggerSchema("Kvíz vizsga kérdés")]
        public string QuizQuestion { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz válaszlehetőség 1")]
        public string QuizAnswer1 { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz válaszlehetőség 2")]
        public string QuizAnswer2 { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz válaszlehetőség 3")]
        public string QuizAnswer3 { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz válaszlehetőség 4")]
        public string QuizAnswer4 { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz kiválasztott válasz")]
        public string QuizSelected { get; set; } = String.Empty;

        [SwaggerSchema("Kvíz helyes válasz")]
        public string QuizSuccess { get; set; } = String.Empty;

        [SwaggerSchema("Módosítás dátuma")]
        public DateTime ModificationDate { get; set; } = DateTime.Now;

        [SwaggerSchema("Kvíz megjelenítése")]
        public bool ShowDetails { get; set; } = false;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}
