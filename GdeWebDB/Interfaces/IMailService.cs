using GdeWebModels;

namespace GdeWebDB.Interfaces
{
    public interface IMailService
    {
        Task<ResultModel> AddContactMail(EmailModel model);

        Task<ResultModel> SendConfirmationEmail(EmailModel model);

        Task<ResultModel> SendConfirmationFinalEmail(EmailModel model);

        Task<ResultModel> SendForgotPasswordEmail(EmailModel model);

        Task<ResultModel> SendUserStateEmail(EmailModel model);

        Task<ResultModel> SendMessage(EmailModel model, Stream? stream, String AttachmentName, String AttachmentMediaType);
    }
}
