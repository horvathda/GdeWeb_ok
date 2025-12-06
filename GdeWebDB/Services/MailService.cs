using GdeWebDB.Interfaces;
using GdeWebDB.Utilities;
using GdeWebModels;
using Microsoft.Extensions.Configuration;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Mail;


namespace GdeWebDB.Services
{
    public class MailService : IMailService
    {
        private ILogService _logService;

        private readonly IConfiguration _configuration;

        public MailService(ILogService logService, IConfiguration configuration)
        {
            this._logService = logService;
            this._configuration = configuration;
        }


        public async Task<ResultModel> AddContactMail(EmailModel model)
        {
            try
            {
                // Create message
                string message = String.Format(contactEmailTemplate(), model.Name, model.Phone, model.FromEmail, model.Subject, model.Message);

                model.Subject = "GDE Edu AI - Weboldal megkeresés";
                model.Message = message;

                await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a központba

                model.ToEmail = model.FromEmail;

                return await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a feladónak is
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "AddContactMail");

                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> SendConfirmationEmail(EmailModel model)
        {
            try
            {
                // Create message
                string token = model.Subject;
                string message = String.Format(confirmationEmailTemplate(), token);

                model.Subject = "GDE Edu AI - Email cím megerősítése";
                model.Message = message;

                return await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a feladónak
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SendConfirmationEmail");

                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> SendConfirmationFinalEmail(EmailModel model)
        {
            try
            {
                // Create message
                string message = String.Format(confirmationFinalEmailTemplate(), model.Subject);

                model.Subject = "GDE Edu AI - Email cím hitelesítve";
                model.Message = message;

                return await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a feladónak
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SendConfirmationFinalEmail");

                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> SendForgotPasswordEmail(EmailModel model)
        {
            try
            {
                // Create message
                string token = model.Subject;
                string message = String.Format(forgotPasswordEmailTemplate(), token);

                model.Subject = "GDE Edu AI - Jelszó megváltoztatása";
                model.Message = message;

                return await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a feladónak
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SendForgotPasswordEmail");

                return ResultTypes.UnexpectedError;
            }
        }


        public async Task<ResultModel> SendUserStateEmail(EmailModel model)
        {
            try
            {
                // Create message
                string message = String.Format(userStateEmailTemplate(), model.Subject, model.Message);

                model.Subject = "GDE Edu AI - Státusz változása";
                model.Message = message;

                return await SendMessage(model, null, String.Empty, String.Empty); // Elküldi a feladónak
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SendUserStateEmail");

                return ResultTypes.UnexpectedError;
            }
        }



        public async Task<ResultModel> SendMessage(EmailModel model, Stream? stream, String AttachmentName, String AttachmentMediaType)
        {
            try
            {
                using (var message = new MailMessage())
                {
                    message.To.Add(new MailAddress(model.ToEmail, model.Name));
                    message.From = new MailAddress(_configuration["MailCredentials:UserName"], "GDE Edu AI");
                    message.Subject = model.Subject;
                    message.Body = model.Message;
                    message.IsBodyHtml = true; // change to true if body msg is in html

                    if (stream != null)
                    {
                        // Melléklet hozzáadása a levelezéshez
                        stream.Seek(0, System.IO.SeekOrigin.Begin);
                        //message.Attachments.Add(new Attachment(stream, "invoice.pdf", "application/pdf"));
                        message.Attachments.Add(new Attachment(stream, AttachmentName, AttachmentMediaType));
                    }

                    using (var client = new SmtpClient())  
                    {
                        client.Host = "smtp.gmail.com"; // Gmail SMTP szerver
                        //client.Host = "smtp.office365.com"; // Office365 SMTP szerver
                        client.Port = 587;
                        client.EnableSsl = true;
                        client.UseDefaultCredentials = false;

                        // Gmail 2022 óta nem enged sima user/pass SMTP-t.
                        // Kapcsold be a fiókon (https://myaccount.google.com/security) a 2 - lépcsős azonosítást, hozz létre App Password-öt (https://myaccount.google.com/apppasswords -> név GdeWeb), és ezt tedd a configba.
                        client.Credentials = new NetworkCredential(
                            _configuration["MailCredentials:UserName"], 
                            _configuration["MailCredentials:Password"]
                        );
                        client.DeliveryMethod = SmtpDeliveryMethod.Network;
                        //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12; // Google-nél nem kell
                        client.Timeout = 600000;

                        try
                        {
                            await client.SendMailAsync(message); // Email sent
                        }
                        catch (Exception exc)
                        {
                            // Email not sent, log exception
                            await _logService.WriteLogToFile(exc, "SendMessage");

                            return ResultTypes.UnexpectedError;
                        }
                    }
                }

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SendMessage");

                return ResultTypes.UnexpectedError;
            }
        }



        private string contactEmailTemplate()
        {
            // hu-HU
            return @"<div style='text-align: center; background-color: #FFFFFF; color: #4E4E4E; padding-top: 10px;'>
    	            <a href='https://eduai.omegacode.cloud'>
                        <img src='https://eduai.omegacode.cloud/img/favicon.png' alt='GDE Edu AI' style='width: 100%; max-width: 128px; height: auto;'>
                    </a>
    	            <h1>Weboldalról üzenet</h1>
        
                    <div style='width: 500px; margin-left: auto; margin-right: auto; text-align: center;'>
                	    <div style='display: flex; margin-top: 10px; text-align: center; width: 100%;'>
                    	    <div style='width: 250px;'>Küldő neve:</div>
                            <div style='width: 250px; word-wrap: break-word;'>{0}</div>
                        </div>
                        <div style='display: flex; margin-top: 10px; text-align: center; width: 100%;'>
                    	    <div style='width: 250px;'>Küldő telefonszáma:</div>
                            <div style='width: 250px; word-wrap: break-word;'>{1}</div>
                        </div>
                        <div style='display: flex; margin-top: 10px; text-align: center; width: 100%;'>
                    	    <div style='width: 250px;'>Küldő email címe:</div>
                            <div style='width: 250px; word-wrap: break-word;'>{2}</div>
                        </div>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <u>Üzenet:</u>
                        </div>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <b>{3}</b>
                        </div>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    {4}
                        </div>
                    </div>
        
                    <p style='padding-bottom: 20px;'>GDE Edu AI</p>
  	            </div>";
        }

        private string confirmationEmailTemplate()
        {
            // hu-HU
            return @"<div style='text-align: center; background-color: #FFFFFF; color: #4E4E4E; padding-top: 10px;'>
    	            <a href='https://eduai.omegacode.cloud'>
                        <img src='https://eduai.omegacode.cloud/img/favicon.png' alt='GDE Edu AI' style='width: 100%; max-width: 128px; height: auto;'>
                    </a>
    	            <h1>E-mail hitelesítés</h1>
        
                    <div style='width: 500px; margin-left: auto; margin-right: auto; text-align: center;'>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <b>A regisztrációja befejezéséhez kattintson az alábbi linkre:</b>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            <a href='{0}' style='flex: 100%; word-wrap: break-word; text-align: center;'><h2>E-mail cím megrősítése</h2></a>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            Ezt az üzenetet azért kapta, mert regisztrált az 
                            <a href='https://eduai.omegacode.cloud'>GDE Edu AI</a> weboldalra.
                        </div>
                    </div>
        
    	            <p style='padding-bottom: 20px;'>GDE Edu AI</p>
  	            </div>";
        }

        private string confirmationFinalEmailTemplate()
        {
            // hu-HU
            return @"<div style='text-align: center; background-color: #FFFFFF; color: #4E4E4E; padding-top: 10px;'>
    	            <a href='https://eduai.omegacode.cloud'>
                        <img src='https://eduai.omegacode.cloud/img/favicon.png' alt='GDE Edu AI' style='width: 100%; max-width: 128px; height: auto;'>
                    </a>
    	            <h1>Kedves {0}!</h1>
        
                    <div style='width: 500px; margin-left: auto; margin-right: auto; text-align: center;'>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <b>Email címe hitelesítve lett, így bejelentkezhet a GDE Edu AI portálra!</b>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            <a href='https://eduai.omegacode.cloud/signin' style='flex: 100%; word-wrap: break-word; text-align: center;'><h2>Bejelentkezés</h2></a>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            Ezt az üzenetet azért kapta, mert regisztrált felhasználója az 
                            <a href='https://eduai.omegacode.cloud'>GDE Edu AI</a> weboldalnak.
                        </div>
                    </div>
        
                    <p style='padding-bottom: 20px;'>GDE Edu AI</p>
  	            </div>";
        }

        private string forgotPasswordEmailTemplate()
        {
            // hu-HU
            return @"<div style='text-align: center; background-color: #FFFFFF; color: #4E4E4E; padding-top: 10px;'>
    	            <a href='https://eduai.omegacode.cloud'>
                        <img src='https://eduai.omegacode.cloud/img/favicon.png' alt='GDE Edu AI' style='width: 100%; max-width: 128px; height: auto;'>
                    </a>
    	            <h1>Jelszó megváltoztatása</h1>
        
                    <div style='width: 500px; margin-left: auto; margin-right: auto; text-align: center;'>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <b>Jelszava megváltoztatásához kattintson az alábbi linkre:</b>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            <a href='{0}' style='flex: 100%; word-wrap: break-word; text-align: center;'><h2>Jelszó megváltoztatásának megrősítése</h2></a>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            Ezt az üzenetet azért kapta, mert regisztrált felhasználója az 
                            <a href='https://eduai.omegacode.cloud'>GDE Edu AI</a> weboldalnak.
                        </div>
                    </div>
        
                    <p style='padding-bottom: 20px;'>GDE Edu AI</p>
  	            </div>";
        }

        private string userStateEmailTemplate()
        {
            // hu-HU
            return @"<div style='text-align: center; background-color: #FFFFFF; color: #4E4E4E; padding-top: 10px;'>
    	            <a href='https://eduai.omegacode.cloud'>
                        <img src='https://eduai.omegacode.cloud/img/favicon.png' alt='GDE Edu AI' style='width: 100%; max-width: 128px; height: auto;'>
                    </a>
    	            <h1>Kedves {0}!</h1>
        
                    <div style='width: 500px; margin-left: auto; margin-right: auto; text-align: center;'>
                        <div style='width: 100%; margin-top: 10px; word-wrap: break-word;'>
                    	    <b>Adminisztrátor által az Ön státusza módosítva lett! Új státusza:</b>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            <h2>{1}</h2>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            Státuszával kapcsolatosan az alábbi email címen keresztül tájékozódhat: <a href='jakab.david@gde.hu' style='flex: 100%; word-wrap: break-word; text-align: center;'>prometheus@gde.hu</a>
                        </div>
                        <div style='width: 100%; margin-top: 20px; word-wrap: break-word;'>
                            Ezt az üzenetet azért kapta, mert regisztrált felhasználója az 
                            <a href='https://eduai.omegacode.cloud'>GDE Edu AI</a> weboldalnak.
                        </div>
                    </div>
        
                    <p style='padding-bottom: 20px;'>GDE Edu AI</p>
  	            </div>";
        }
    }
}