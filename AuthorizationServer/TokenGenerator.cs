using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace AuthorizationServer
{
    public class TokenGenerator
    {
        public string CreateAccessToken(string dpopToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(dpopToken);
            var dpopHeader = jwtToken.Header;
            var key = Convert.FromBase64String("NTNv7j0TuYARvmNMmWXo6fKvM4o6nvaUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiTqJACs1J0apruOOJCggOtkjB4c");//Encoding.ASCII.GetBytes("tajni_kljuc_za_potpisivanje");

            var jwkExtractedValue = dpopHeader["jwk"];
            var jwk = new JsonWebKey(jwkExtractedValue as string);
            var thumbprint = jwk.ComputeJwkThumbprint();

            var jktValue = new { jkt = thumbprint };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("cnf", JsonSerializer.Serialize(jktValue))
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) //nadodano
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
