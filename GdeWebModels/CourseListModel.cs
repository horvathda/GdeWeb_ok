using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Kurzusok lista osztálya")]
    public class CourseListModel
    {
        [SwaggerSchema("Kurzusok listája")]
        public List<CourseModel> CourseList { get; set; } = new List<CourseModel>();

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel() { Success = true, ErrorMessage = "" };
    }
}
