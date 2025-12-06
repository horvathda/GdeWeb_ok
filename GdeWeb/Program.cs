using Blazored.LocalStorage;
using GdeWeb.Components;
using GdeWeb.Interfaces;
using GdeWeb.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using MudBlazor.Services;

namespace GdeWeb
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Read appsettings.json apiUrl
            var configuration = new ConfigurationBuilder()
                .SetBasePath(builder.Environment.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();
            string apiUrl = configuration.GetValue<string>("apiUrl") ?? "";

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();

            // Local storage szolgáltatás hozzáadása
            builder.Services.AddBlazoredLocalStorage();

            // Szolgáltatások hozzáadása
            builder.Services.AddRazorPages();
            builder.Services.AddServerSideBlazor().AddCircuitOptions(options => { options.DetailedErrors = true; });

            // Http GetIP
            builder.Services.AddHttpContextAccessor();

            // Mudblazor
            builder.Services.AddMudServices();

            // Service registrations
            builder.Services.AddTransient<IBadgeService, BadgeService>();
            builder.Services.AddTransient<ISnackbarService, Services.SnackbarService>();
            builder.Services.AddHttpClient<IAuthService, AuthService>(c => c.BaseAddress = new Uri(apiUrl));
            builder.Services.AddHttpClient<IUserService, UserService>(c => c.BaseAddress = new Uri(apiUrl));
            builder.Services.AddHttpClient<ITrainingService, TrainingService>(c => c.BaseAddress = new Uri(apiUrl));
            builder.Services.AddHttpClient<IMessageService, MessageService>(c => c.BaseAddress = new Uri(apiUrl));

            // 1) Hitelesítés (cookie példa)
            // Authentication Core - For authentication
            builder.Services
                .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/signin";
                    //options.AccessDeniedPath = "/forbidden";
                    // további opciók...
                });

            // 2) Jogosultságkezelés
            // ⚠️ NINCS Cookie/Bearer auth itt
            builder.Services.AddAuthorization();                     // kell az [Authorize]-hoz

            // Cascading Authentication
            builder.Services.AddCascadingAuthenticationState(); // kell az AuthorizeView-hoz

            // Authentication Service
            builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthentication>();
            builder.Services.AddScoped<CustomAuthentication>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            // Middleware-k
            app.UseStaticFiles();

            app.UseRouting(); // Hozzáadjuk a routingot

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseAntiforgery(); // Hozzáadjuk az antiforgery middleware-t
            app.MapControllers(); // Térképezzük fel a kontrollereket

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            // Refresh
            app.MapFallbackToFile("/");

            app.Run();
        }
    }
}
