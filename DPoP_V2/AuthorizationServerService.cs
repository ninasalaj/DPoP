using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace DPoP_V2
{
    public class AuthorizationServerService
    {
        public (JwtSecurityToken token, string tokenString) CreateAccessToken(string dpopToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(dpopToken);
            var dpopHeader = jwtToken.Header;

            var jwkExtractedValue = dpopHeader["jwk"];
            var jwk = new JsonWebKey(jwkExtractedValue as string);
            var thumbprint = jwk.ComputeJwkThumbprint();

            var jktValue = new { jkt = thumbprint };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("cnf", JsonSerializer.Serialize(jktValue)) //vjerojatno treba dorada
                }),
                Expires = DateTime.UtcNow.AddHours(1)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return (token as JwtSecurityToken, tokenHandler.WriteToken(token));
        }
    }
}
