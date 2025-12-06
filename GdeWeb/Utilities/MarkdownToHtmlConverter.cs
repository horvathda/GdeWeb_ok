using Markdig;
using System.Text;

namespace GdeWeb.Utilities
{
    public class MarkdownToHtmlConverter
    {
        public static string ConvertMarkdownToHtml(string markdown)
        {
            // Use Markdig to convert the Markdown to HTML
            //var pipeline = new MarkdownPipelineBuilder().UseAdvancedExtensions().Build();
            //string htmlContent = Markdown.ToHtml(markdown, pipeline);

            // Use Markdig to convert the Markdown to HTML
            var pipeline = new MarkdownPipelineBuilder()
                .UseAdvancedExtensions() // táblázat, definíciólista, stb.
                .UseMathematics()        // képletek támogatása
                .Build();
            string htmlContent = Markdown.ToHtml(markdown, pipeline);

            // Add CSS styles to the HTML content
            StringBuilder htmlBuilder = new StringBuilder();
            htmlBuilder.AppendLine("<div class=\"markdown-content\">");
            htmlBuilder.Append(htmlContent);
            htmlBuilder.AppendLine("</div>");

            return htmlBuilder.ToString();
        }
    }
}
