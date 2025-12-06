using GdeWebModels;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace GdeWebAPI.Utilities
{
    /// <summary>
    /// Közműveletek (token-kezelés, formázás, stb.) a webalkalmazás számára.
    /// </summary>
    public class Utilities
    {
        /// <summary>
        /// ENCRYPT PASSWORD
        /// </summary>
        #region ENCRYPT PASSWORD
        public static string EncryptPassword(string password)
        {
            SHA512? provider = SHA512.Create();
            string salt = "Gd3R@nd0mS@lt";
            byte[] code = Encoding.UTF32.GetBytes(salt + password);
            string code_string = string.Join(" ", code);
            byte[] bytes = provider.ComputeHash(code);
            string bytes_string = string.Join(" ", bytes);
            string converted = BitConverter.ToString(bytes).Replace("-", "").ToLower();
            return converted;
        }
        #endregion


        /// <summary>
        /// GET USER ID FROM TOKEN
        /// </summary>
        #region GET USER ID FROM TOKEN
        public static int GetUserIdFromToken(string token)
        {
            try
            {
                JwtSecurityTokenHandler? handler = new JwtSecurityTokenHandler();

                JwtSecurityToken? jwtToken = handler.ReadJwtToken(token);

                int userId = int.Parse(jwtToken.Claims.Where(x => x.Type == "UserId").Select(x => x.Value).First());

                return userId;
            }
            catch
            {
                return -1;
            }
        }
        #endregion


        /// <summary>
        /// GET USER GUID FROM TOKEN
        /// </summary>
        #region GET USER GUID FROM TOKEN
        public static string GetUserGuidFromToken(string token)
        {
            try
            {
                JwtSecurityTokenHandler? handler = new JwtSecurityTokenHandler();

                JwtSecurityToken? jwtToken = handler.ReadJwtToken(token);

                string userGuid = jwtToken.Claims.Where(x => x.Type == "UserGuid").Select(x => x.Value).First();

                return userGuid;
            }
            catch
            {
                return String.Empty;
            }
        }
        #endregion


        /// <summary>
        /// GENERATE TOKEN
        /// </summary>
        #region GENERATE TOKEN
        public static string GenerateToken(LoginResultModel loginResult, IConfiguration configuration)
        {
            List<Claim>? claims = new List<Claim>
            {
                new Claim("UserId", loginResult.Id.ToString()),
                new Claim("UserGuid", loginResult.Guid.ToString())
            };

            foreach (LoginRoleModel? role in loginResult.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            string jwtKey = configuration["Jwt:Key"] ?? String.Empty;
            string jwtExpire = configuration["Jwt:ExpireInHours"] ?? String.Empty;

            SymmetricSecurityKey? key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            SigningCredentials? signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            JwtSecurityToken? token = new JwtSecurityToken(
                configuration["Jwt:Issuer"],
                configuration["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddHours(double.Parse(jwtExpire)),
                signingCredentials: signIn);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion


        /// <summary>
        /// GET PATH
        /// </summary>
        #region GET PATH
        public static string GetPath(string url)
        {
            string guidPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "wwwroot");
            string urlPath = url.Replace("/", "\\");
            return System.IO.Path.Combine(guidPath, urlPath);
        }
        #endregion
    }
}
