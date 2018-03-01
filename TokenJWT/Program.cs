namespace TokenJWT
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Security.Claims;
    using System.Text;
    using Microsoft.IdentityModel.Logging;
    using Microsoft.IdentityModel.Tokens;

    class Program
    {
        static void Main(string[] args)
        {
            // show secured inforamtions in exceptions
            IdentityModelEventSource.ShowPII = true;

            // increase max Console.ReadLine() max lenght
            Console.SetIn(new StreamReader(Console.OpenStandardInput(),
                Console.InputEncoding,
                false,
                1024));

            var securedToken = CreateJwtToken();
            Console.WriteLine($"JWT Token : {securedToken}");

            Console.WriteLine("JWT Token to validate : ");
            var tokenToValidate = Console.ReadLine();
            Console.WriteLine("JWT Token secret : ");
            var secret = Console.ReadLine();

            string username;
            var isTokenValid = ValidateJwtToken(tokenToValidate, secret, out username);

            if (isTokenValid)
            {
                Console.WriteLine($"The JWT token is valid. Username = {username}");
            }
            else
            {
                Console.WriteLine("Invalid JWT token.");
            }

            Console.ReadLine();
        }

        private static string CreateJwtToken()
        {
            var secret = Guid.NewGuid().ToString();
            Console.WriteLine($"secret : {secret}");

            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                SecurityAlgorithms.HmacSha256Signature);

            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, "jdupont"), // username
                new Claim("name", "Jean Dupont"),
                new Claim(ClaimTypes.Email, "jean.dupont@site")
            });

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "client_id",
                Audience = "https://api.site",
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(20),
                SigningCredentials = signingCredentials,
                Subject = claimsIdentity
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var token = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var securedToken = jwtSecurityTokenHandler.WriteToken(token);

            Console.WriteLine($"plain : {token}");

            return securedToken;
        }

        private static bool ValidateJwtToken(string token, string secret, out string username)
        {
            username = null;

            var tokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                RequireExpirationTime = false,
                ValidateAudience = false,
                ValidateActor = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true
            };

            SecurityToken validatedToken;
            ClaimsPrincipal principal;

            try
            {
                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                principal = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
                Console.WriteLine($"Validated token : {validatedToken}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error : {ex}");
                return false;
            }

            var isAuthenticated = principal?.Identity != null && principal.Identity.IsAuthenticated;

            if (isAuthenticated)
            {
                username = principal.Identity.Name;
            }

            return isAuthenticated;
        }
    }
}
