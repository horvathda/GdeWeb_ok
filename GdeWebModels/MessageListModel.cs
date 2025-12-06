using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    [SwaggerSchema("Üzenetek lista osztálya")]
    public class MessageListModel
    {
        [SwaggerSchema("Kurzus azonosítója embeddinghez")]
        public int CourseId { get; set; } = 0;

        [SwaggerSchema("Kurzus generálás vagy hagyományos prompt")]
        public bool GeneratePrompt { get; set; } = false;

        [SwaggerSchema("Üzenetek listája")]
        public List<MessageModel> MessageList { get; set; } = new List<MessageModel>();
    }
}