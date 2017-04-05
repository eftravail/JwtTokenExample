using System;
using System.Collections.Generic;
using System.Linq;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication4
{
    class Program
    {
        static void Main(string[] args)
        {
            var issuer = "http://my.tokenissuer.com";
            var plainTextSecurityKey = "This is my shared, not so secret, secret!";
            var signingKey = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(plainTextSecurityKey));
            var signingCredentials = new SigningCredentials(signingKey,
                SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            var claimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, "myemail@myprovider.com"),
                new Claim(ClaimTypes.Role, "Administrator"),
            }, "Custom");

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                AppliesToAddress = "http://my.website.com",
                TokenIssuerName = issuer,
                Subject = claimsIdentity,
                SigningCredentials = signingCredentials,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var plainToken = tokenHandler.CreateToken(securityTokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);

            

            WriteToken("Plain Token:", plainToken.ToString());

            WriteToken("Signed and Encoded Token:", signedAndEncodedToken);

            //Doing this to see if this code pattern generates a different Token
            var jwtToken = tokenHandler.WriteToken(new JwtSecurityToken(issuer, "Any", claimsIdentity.Claims, plainToken.ValidFrom, plainToken.ValidTo, signingCredentials));
            WriteToken("JwtSecurity Token:", jwtToken.ToString());

            WritePause();
            WriteDivider();

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                {
                    "http://my.website.com",
                    "http://my.otherwebsite.com"
                },
                ValidIssuers = new string[]
                {
                    "http://my.tokenissuer.com",
                    "http://my.othertokenissuer.com"
                },
                IssuerSigningKey = signingKey
            };

            SecurityToken validatedToken;
            tokenHandler.ValidateToken(signedAndEncodedToken,
                tokenValidationParameters, out validatedToken);

            WriteToken("Validated Token:", validatedToken.ToString());
            Console.ReadLine();
        }

        private static void WritePause()
        {
            Console.WriteLine();
            Console.WriteLine("Press the ENTER key to continue...");
            Console.ReadLine();
        }

        private static void WriteDivider()
        {
            Console.WriteLine();
            Console.WriteLine(new string('-', 15));
            Console.WriteLine();
        }
        private static void WriteToken(string description, string tokenValue)
        {
            if (!string.IsNullOrEmpty(description))
            {
                if (!description.EndsWith(":"))
                    description = description + ":";

                Console.WriteLine(description);
            }

            if (!string.IsNullOrEmpty(tokenValue))
            {
                Console.WriteLine(tokenValue);
                Console.WriteLine();
                Console.WriteLine();
            }
        }
    }
}
