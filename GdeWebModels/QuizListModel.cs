using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Kvízek lista osztálya")]
    public class QuizListModel
    {
        [SwaggerSchema("Kvízek listája")]
        public List<QuizModel> QuizList { get; set; } = new List<QuizModel>();

        [SwaggerSchema("Kvízek lekérdezett darabszáma")]
        public int Count { get; set; } = 0;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}
