using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace AuthorizationServer
{
    public class ProofValidator
    {
        public bool VerifyDpopProof(string dpopProof, string method, string uri)
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

            if (!jwtToken.Payload.ContainsKey("htu"))
                return false;

            if (jwtToken.Payload["htu"].ToString() != uri)
                return false;

            if (!jwtToken.Payload.ContainsKey("htm"))
                return false;

            if (jwtToken.Payload["htm"].ToString().ToLower() != method.ToLower())
                return false;

            var jwk = jwtToken.Header["jwk"].ToString();
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(jwk);

            //Validate jwt signature using key in jose header
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
    }
}
