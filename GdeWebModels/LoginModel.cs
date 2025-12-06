using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebModels
{
    [SwaggerSchema("Login osztálya")]
    public class LoginModel
    {
        [SwaggerSchema("User email név")]
        public string Email { get; set; } = String.Empty;

        [SwaggerSchema("Login jelszó")]
        public string Password { get; set; } = String.Empty;
    }
}
