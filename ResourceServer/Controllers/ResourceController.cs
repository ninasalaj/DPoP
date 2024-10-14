using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ResourceServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController : ControllerBase 
    {
        [HttpGet("resource")]
        public IActionResult GetResource([FromHeader(Name = "Authorization")] string token, [FromHeader(Name = "DPoP")] string dpopProof)
        {
            if (ValidateAccessToken(token) && VerifyDpopProof(dpopProof, token))
            {
                return Ok("Protected resource");
            }
            return Unauthorized();
        }

        private bool ValidateAccessToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Convert.FromBase64String("NTNv7j0TuYARvmNMmWXo6fKvM4o6nvaUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiTqJACs1J0apruOOJCggOtkjB4c");

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool VerifyDpopProof(string dpopProof, string accessToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(dpopProof);
            var dpopHeader = jwtToken.Header;

            //check "typ"
            if (!jwtToken.Header.ContainsKey("typ") || jwtToken.Header["typ"].ToString() != "dpop+jwt")
                return false;

            //check algorithm
            if (!jwtToken.Header.ContainsKey("alg"))
                return false;

            var algorithms = new string[] { "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" };
            var joseAlg = jwtToken.Header["alg"].ToString();

            if (joseAlg == "none")
                return false;

            if (!Array.Exists(algorithms, alg => alg == joseAlg))
                return false;

            if (jwtToken.Payload["ath"].ToString() != GenerateAccessTokenThumbprint(accessToken))
                return false;

            //key in jose header is used to validate JWT signature and cnf claim
            var jwk = jwtToken.Header["jwk"];
            var jsonWebKey = new JsonWebKey(jwk as string);
            var thumbprint = Convert.ToBase64String(jsonWebKey.ComputeJwkThumbprint());

            if (thumbprint != GetCnfClaim(accessToken))
                return false;
            
            var jwtHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = jsonWebKey,
                ValidateIssuerSigningKey = true,
                RequireAudience = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false
            };

            jwtHandler.ValidateToken(dpopProof, validationParameters, out var validatedToken);

            if (validatedToken == null)
                return false;

            return true;
        }

        private string GenerateAccessTokenThumbprint(string accessToken)
        {
            using (var sha256 = SHA256.Create())
            {
                var tokenBytes = Encoding.UTF8.GetBytes(accessToken);
                var hash = sha256.ComputeHash(tokenBytes);

                //returns Base64Url encoded hash (so it can be used within JWT)
                return Base64UrlEncoder.Encode(hash);
            }
        }

        private string GetCnfClaim(string accessToken) 
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(accessToken);
            var cnfClaim = jwtToken.Payload["cnf"].ToString();

            var jsonWebKey = JsonSerializer.Deserialize<JwkToken>(cnfClaim);

            return jsonWebKey.jkt;
        }
    }

    public class JwkToken
    {
        public string jkt { get; set; }
    }
}
