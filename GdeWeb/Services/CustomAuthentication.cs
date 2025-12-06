using GdeWebModels;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.BearerToken;
using System.Security.Principal;
using GdeWeb.Interfaces;
using Blazored.LocalStorage;

namespace GdeWeb.Services
{
    public class CustomAuthentication : AuthenticationStateProvider
    {
        // Mi az a helyi tárhely (Local storage)?

        // A helyi tároló egy tárolóobjektum elérésére szolgáló tulajdonság, amely az adatok tárolására és a felhasználó böngészőjéből való lekérésére szolgál.Csak a kliens oldalon érhető el, a szerver oldalon nem, mint egy cookie.
        // A helyi tárhelyen tárolt adatok elérhetők. Minden oldal ugyanahhoz a domainhez tartozik, hacsak a felhasználó nem törli manuálisan. Annak ellenére, hogy a felhasználó bezárja a böngészőt, az adatok legközelebb elérhetők lesznek.

        // Mi az a munkamenet-tárolás (Session storage)?

        // A munkamenet-tárolás majdnem ugyanaz, mint a helyi tárhely. Az egyetlen különbség az, hogy a munkamenet tárhelye törlődik, ha a felhasználó bezárja a böngészőablakot.


        private readonly ILocalStorageService _localStorage;

        private IAuthService _authenticationService { get; set; }

        private ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public CustomAuthentication(IAuthService authenticationService, ILocalStorageService localStorage)
        {
            _authenticationService = authenticationService;
            _localStorage = localStorage;
        }

        //Google Auth
        public async Task MarkUserAsAuthenticated(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                await MarkUserAsLoggedOut();
                return;
            }

            await _localStorage.SetItemAsync("token", token);

            var loginTokenModel = new LoginTokenModel { Token = token };
            LoginUserModel loggedUser = await _authenticationService.GetUserFromToken(loginTokenModel);

            ClaimsIdentity identity = GetClaimsIdentity(loggedUser);

            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }


        /// <summary>
        /// Autentikációs állapot lekérése
        /// </summary>
        /// <returns></returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                string? accessToken = await _localStorage.GetItemAsync<String>("token");

                if (accessToken == null)
                    return await Task.FromResult(new AuthenticationState(_anonymous));

                ClaimsIdentity identity;

                if (accessToken != null && accessToken != string.Empty)
                {
                    LoginTokenModel loginTokenModel = new LoginTokenModel() { Token = accessToken };
                    LoginUserModel user = await _authenticationService.GetUserFromToken(loginTokenModel);
                    identity = GetClaimsIdentity(user);
                }
                else
                {
                    identity = new ClaimsIdentity();
                }

                ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);

                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
                return await Task.FromResult(new AuthenticationState(claimsPrincipal));
            }
            catch
            {
                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
                return await Task.FromResult(new AuthenticationState(_anonymous));
            }
        }

        /// <summary>
        /// Autentikált felhasználó lekérése
        /// </summary>
        /// <returns></returns>
        public async Task<LoginUserModel> GetAuthenticatedUserAsync()
        {
            string? accessToken = await _localStorage.GetItemAsync<String>("token");

            if (!string.IsNullOrEmpty(accessToken))
            {
                LoginTokenModel loginTokenModel = new LoginTokenModel() { Token = accessToken };
                LoginUserModel user = await _authenticationService.GetUserFromToken(loginTokenModel);

                return await Task.FromResult(user);
            }
            else
            {
                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
                return await Task.FromResult(new LoginUserModel());
            }
        }

        /// <summary>
        /// Felhasználó autentikálttá jelölése
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task MarkUserAsAuthenticated(LoginResultModel user)
        {
            await _localStorage.SetItemAsync("token", user.Token);

            LoginTokenModel loginTokenModel = new LoginTokenModel() { Token = user.Token };
            LoginUserModel loggedUser = await _authenticationService.GetUserFromToken(loginTokenModel);

            ClaimsIdentity identity = GetClaimsIdentity(loggedUser);

            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        /// <summary>
        /// Felhasználó kijelentkezetté jelölése
        /// </summary>
        /// <returns></returns>
        public async Task MarkUserAsLoggedOut()
        {
            await _localStorage.RemoveItemAsync("token");

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
        }

        /// <summary>
        /// Felhasználó claimek létrehozása
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private ClaimsIdentity GetClaimsIdentity(LoginUserModel user)
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();

            if (user != null && user.Email != null)
            {
                List<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Sid, user.Id.ToString())); // Id
                claims.Add(new Claim(ClaimTypes.Name, user.FirstName)); // First name
                claims.Add(new Claim(ClaimTypes.GivenName, String.IsNullOrEmpty(user.LastName) ? "" : user.LastName)); // Last name
                claims.Add(new Claim(ClaimTypes.Email, user.Email)); // Email
                claims.Add(new Claim(ClaimTypes.Dns, String.IsNullOrEmpty(user.Guid.ToString()) ? "" : user.Guid.ToString())); // Guid
                foreach (LoginRoleModel role in user.Roles.Where(r => !string.IsNullOrWhiteSpace(r.Name)))
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.Name)); // Jogosultságok
                }

                claimsIdentity = new ClaimsIdentity(claims, "CustomAuth");
            }

            return claimsIdentity;
        }
    }
}
