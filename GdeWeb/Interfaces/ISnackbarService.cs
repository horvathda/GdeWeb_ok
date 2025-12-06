using MudBlazor;

namespace GdeWeb.Interfaces
{
    public interface ISnackbarService
    {
        public void ShowSnackbar(Severity severity, string message, int pageWidth = 700, bool clearAfterNavigation = true);
    }
}