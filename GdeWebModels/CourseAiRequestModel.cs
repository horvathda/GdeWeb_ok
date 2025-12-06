using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    public class CourseAiRequestModel
    {
        public string Topic { get; set; } = "";
        public int Duration { get; set; } = 45;      // pl. 45 másodperc
        public int MinScenes { get; set; } = 5;         // pl. 5 darab videó jelenet
        public int QuizCount { get; set; } = 5;         // pl. 5 darab kvíz kérdés
        public string Language { get; set; } = "magyar";
    }
}
