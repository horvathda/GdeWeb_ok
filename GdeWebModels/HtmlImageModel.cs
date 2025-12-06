using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Fájl osztálya")]
    public class HtmlImageModel
    {
        [SwaggerSchema("Fájl neve")]
        public string Name { get; set; } = String.Empty;

        [SwaggerSchema("Fájl mérete")]
        public long Size { get; set; } = 0;

        [SwaggerSchema("Fájl adat")]
        public byte[] Data { get; set; } = default!;

        [SwaggerSchema("Művelet sikeressége")]
        public ResultModel Result { get; set; } = new ResultModel();
    }
}
