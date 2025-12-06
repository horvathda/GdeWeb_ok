using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Felhasználó esemény osztálya")]
    public class UserEventModel
    {
        [SwaggerSchema("Esemény kurzus azonosítója")]
        public int CourseId { get; set; } = 0;

        [SwaggerSchema("Badge azonosítója")]
        public string BadgeId { get; set; } = String.Empty;

        [SwaggerSchema("Módosítás dátuma")]
        public DateTime ModificationDate { get; set; } = DateTime.Now;
    }
}
