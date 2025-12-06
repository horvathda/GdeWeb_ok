using Microsoft.AspNetCore.Components;
using MudBlazor;
using GdeWeb.Interfaces;

namespace GdeWeb.Services
{
    public class SnackbarService : ISnackbarService
    {
        private readonly ISnackbar snackbar;

        public SnackbarService(ISnackbar snackbar)
        {
            this.snackbar = snackbar;

            snackbar.Configuration.PositionClass = Defaults.Classes.Position.TopRight;
            snackbar.Configuration.SnackbarVariant = Variant.Filled;
            snackbar.Configuration.MaxDisplayedSnackbars = 5;
            snackbar.Configuration.ShowTransitionDuration = 100;
            snackbar.Configuration.HideTransitionDuration = 100;
            snackbar.Configuration.VisibleStateDuration = 7000; /*3500;*/
            snackbar.Configuration.ClearAfterNavigation = true;
            snackbar.Configuration.PreventDuplicates = false;
            snackbar.Configuration.BackgroundBlurred = false;
        }

        public void ShowSnackbar(Severity severity, string message, int pageWidth = 700, bool clearAfterNavigation = true)
        {
            if (pageWidth > 720)
            {
                // Desktop
                snackbar.Configuration.PositionClass = Defaults.Classes.Position.TopRight;
                snackbar.Configuration.MaxDisplayedSnackbars = 5;
            }
            else
            {
                // Mobile
                snackbar.Configuration.PositionClass = Defaults.Classes.Position.TopCenter;
                snackbar.Configuration.MaxDisplayedSnackbars = 3;
            }

            snackbar.Configuration.ClearAfterNavigation = clearAfterNavigation;
            snackbar.Add((MarkupString)message, severity);
        }
    }
}