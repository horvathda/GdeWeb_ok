using GdeWebModels;

namespace GdeWeb.Interfaces
{
    /// <summary>
    /// Üzenetküldő szolgáltatás
    /// </summary>
    public interface IMessageService
    {
        /// <summary>
        /// Üzenet küldése
        /// </summary>
        /// <param name="url"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        Task<ResultModel> AddContactMail(EmailModel model);
    }
}