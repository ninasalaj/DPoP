using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Client
{
    public class TokenGenerator
    {
        public string GenerateProofToken(string htm, string htu)
        {
            var payload = new JwtPayload();
            var jwk = SecurityKeyInfo.Jwk;

            //note that only parts of the request included in the DPoP JWT are HTTP method and URI
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("htm", htm),
                new Claim("htu", htu),
                new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            };
            payload.AddClaims(claims);

            var token = new JwtSecurityToken(GenerateDPoPHeader(SecurityKeyInfo.SigningAlgorithm, JsonSerializer.Serialize(jwk)), payload);

            return GenerateSignedTokenString(token.EncodedHeader,
                token.EncodedPayload, new SigningCredentials(SecurityKeyInfo.Key, SecurityKeyInfo.SigningAlgorithm));
        }

        private string GenerateSignedTokenString(string encodedHeader, string encodedPayload, SigningCredentials credentials)
        {
            var encodedSignature = Microsoft.IdentityModel.JsonWebTokens.JwtTokenUtilities.CreateEncodedSignature(
                input: string.Concat(encodedHeader, ".", encodedPayload), signingCredentials: credentials);
            return string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        }

        private JwtHeader GenerateDPoPHeader(string alg, string jwk)
        {
            return new JwtHeader()
            {
                { JwtHeaderParameterNames.Typ, "dpop+jwt" },
                { JwtHeaderParameterNames.Alg, alg },
                { JwtHeaderParameterNames.Jwk, jwk }
            };
        }

        public string GenerateDpopProofBindedToAccessToken(string httpMethod, string url, string accessToken)
        {
            var payload = new JwtPayload();
            var jwk = SecurityKeyInfo.Jwk;
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim("ath", GenerateAccessTokenThumbprint(accessToken)) //binding to access token
            };
            payload.AddClaims(claims);

            var token = new JwtSecurityToken(GenerateDPoPHeader(SecurityKeyInfo.SigningAlgorithm, JsonSerializer.Serialize(jwk)), payload);

            return GenerateSignedTokenString(token.EncodedHeader,
                token.EncodedPayload, new SigningCredentials(SecurityKeyInfo.Key, SecurityKeyInfo.SigningAlgorithm));
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
    }
}
