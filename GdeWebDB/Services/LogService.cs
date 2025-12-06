using GdeWebDB.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebDB.Services
{
    public class LogService : ILogService
    {
        public async Task WriteLogToFile(Exception ex, string details)
        {
            try
            {
                string newDetails = string.Empty;

                CollectExceptionMessage(ref newDetails, ex);

                using (StreamWriter streamWriter = new StreamWriter("errorlog.txt", true))
                {
                    await streamWriter.WriteLineAsync($"[{DateTime.Now.ToString("yyyy.MM.dd HH:mm:ss")}][{newDetails}][{details}]");
                    await streamWriter.FlushAsync();
                    streamWriter.Close();
                }
            }
            catch
            {
            }
        }

        public async Task WriteMessageLogToFile(String message, string details)
        {
            try
            {
                string newDetails = message;

                using (StreamWriter streamWriter = new StreamWriter("errorlog.txt", true))
                {
                    await streamWriter.WriteLineAsync($"[{DateTime.Now.ToString("yyyy.MM.dd HH:mm:ss")}][{newDetails}][{details}]");
                    await streamWriter.FlushAsync();
                    streamWriter.Close();
                }
            }
            catch
            {
            }
        }

        private void CollectExceptionMessage(ref string message, Exception exception)
        {
            message += " INNER EXCEPTION: " + exception.Message + " ( " + exception.ToString() + " )";

            if (exception.InnerException != null)
            {
                CollectExceptionMessage(ref message, exception.InnerException);
            }
        }
    }
}
