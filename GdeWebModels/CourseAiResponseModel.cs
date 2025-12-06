using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    public class CourseAiResponseModel
    {
        public string title { get; set; } = "";
        public string description { get; set; } = "";
        public string content { get; set; } = "";   // HTML
        public List<MovieScene> movie { get; set; } = new();
        public Music music { get; set; } = new();
        public List<QuizItem> quiz { get; set; } = new();
    }

    public class MovieScene
    {
        public int scene { get; set; }
        public string time { get; set; } = "";
        public string visuals { get; set; } = "";
        public string narration { get; set; } = "";
    }

    public class Music
    {
        public string style { get; set; } = "";
        public string tempo { get; set; } = "";
        public string mood { get; set; } = "";
    }

    public class QuizItem
    {
        public string question { get; set; } = "";
        public List<QuizAnswer> answers { get; set; } = new();
    }

    public class QuizAnswer
    {
        public string text { get; set; } = "";
        public bool correct { get; set; }
    }
}
