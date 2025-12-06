using GdeWebModels;

namespace GdeWebDB.Utilities
{
    public static class ResultTypes
    {
        public static ResultModel UnexpectedError = new ResultModel
        {
            Success = false,
            ErrorMessage = "Váratlan hiba történt a művelet során!"
        };

        public static ResultModel UserAuthenticateError = new ResultModel
        {
            Success = false,
            ErrorMessage = "Hiba történt a felhasználó azonosítása közben!"
        };

        public static ResultModel NotFound = new ResultModel
        {
            Success = false,
            ErrorMessage = "Eredmény nem található!"
        };
    }
}