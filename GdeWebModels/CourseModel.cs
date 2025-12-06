using Newtonsoft.Json;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Kurzus osztálya")]
    public class CourseModel
    {
        [SwaggerSchema("Kurzus azonosítója")]
        public int CourseId { get; set; } = 0;

        [SwaggerSchema("Kurzus megnevezése")]
        public string CourseTitle { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus rövid leírása")]
        public string CourseDescription { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus HTML dokumentuma")]
        public string CourseFile { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus dokumentum szövege")]
        public string CourseFileText { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus videó médiaelem")]
        public string CourseMedia { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus videó médiaelem szövege")]
        public string CourseMediaText { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus médiaelem hossza")]
        public int CourseMediaDuration { get; set; } = 0;

        [SwaggerSchema("Kurzus összefoglaló kulcsszavak")]
        public string CourseSummaryKeywords { get; set; } = String.Empty;

        [SwaggerSchema("Kurzus AI prompt adatok")]
        public CourseAiRequestModel CourseAiRequest { get; set; } = new CourseAiRequestModel();

        [SwaggerSchema("Kurzus AI válasz adatok")]
        public CourseAiResponseModel CourseAiResponse { get; set; } = new CourseAiResponseModel();

        [SwaggerSchema("Kurzus vektor adatbázis")]
        public string CourseDB { get; set; } = String.Empty;

        [SwaggerSchema("Módosítás dátuma")]
        public DateTime ModificationDate { get; set; } = DateTime.Now;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };

        [SwaggerSchema("Kurzus AI prompt adatok json string formátuma")]
        // Property to hold the JSON string in the database
        [Newtonsoft.Json.JsonIgnore]
        public string CourseAiRequestJson
        {
            get => String.Empty;
            set
            {
                CourseAiRequest = string.IsNullOrEmpty(value)
                    ? new CourseAiRequestModel()
                    : JsonConvert.DeserializeObject<CourseAiRequestModel>(value) ?? new CourseAiRequestModel();
            }
        }

        [SwaggerSchema("Kurzus AI válasz adatok json string formátuma")]
        // Property to hold the JSON string in the database
        [Newtonsoft.Json.JsonIgnore]
        public string CourseAiResponseJson
        {
            get => String.Empty;
            set
            {
                CourseAiResponse = string.IsNullOrEmpty(value) 
                    ? new CourseAiResponseModel() 
                    : JsonConvert.DeserializeObject<CourseAiResponseModel>(value) ?? new CourseAiResponseModel();
            }
        }
    }
}
