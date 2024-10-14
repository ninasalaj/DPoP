using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace DPoP_V2
{
    public class ClientService
    {
        static HttpClient httpClient = new HttpClient();

        //pošalji zahtjev autorizacijskom poslužitelju za pristupni token
        public async Task GetAccessToken()
        {
            var jwk = new JsonWebKey
            {
                Kty = "EC",
                X = Base64UrlEncoder.Encode(KeyPair.PublicKey.X),
                Y = Base64UrlEncoder.Encode(KeyPair.PublicKey.Y),
                Crv = "P-256"
            };

            var jwtHeader = new JwtHeader()
                {
                    { JwtHeaderParameterNames.Typ, "dpop+jwt" },
                    { JwtHeaderParameterNames.Alg, "ES256" },
                    { JwtHeaderParameterNames.Jwk, JsonSerializer.Serialize(jwk) }
                };

            var payload = new JwtPayload();

            //note that only parts of the request included in the DPoP JWT are HTTP method and URI
            var claims = new[]
            {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("htm", "POST"), 
                    //htu
                    new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                    //ath, nonce
            };
            payload.AddClaims(claims);

            var token = new JwtSecurityToken(jwtHeader, payload);

            var tokenString = string.Concat(token.Header.Base64UrlEncode(), ".", token.EncodedPayload, ".");

            string accessToken;
            //valid DPoP proof demonstrates to the server that the client holds the private key that was used to sign the DPoP proof JWT
            // => potrebno je potpisati taj JWT 
            using (var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5208/AuthorizationServer/GetAccessToken"))
            {
                request.Headers.Add("DPoP", tokenString);
                //u header još dodati host i conent-type

                request.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("client_id", "s6BhdRkqt"),
                    new KeyValuePair<string, string>("code", "SplxlOBeZQQYbYS6WxSbIA"),
                    new KeyValuePair<string, string>("redirect_uri", "https://client.example.com/cb"),
                    new KeyValuePair<string, string>("code_verifier", "bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz")
                });


                using (var response = await httpClient.SendAsync(request))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                    }

                    accessToken = await response.Content.ReadAsStringAsync();
                }
            };

            //kreiraj novi dpop token za pristup resursu
            var resourceJwtPayload = new JwtPayload();
            var resouceTokenClaims = new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("htm", "GET"),
                    new Claim("htu", "https://resouce.example.com/resource"),
                    new Claim("ath", accessToken),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
                };
            resourceJwtPayload.AddClaims(resouceTokenClaims);
            //reuse old header
            var resourceToken = new JwtSecurityToken(jwtHeader, resourceJwtPayload);

            //sign token
            var encodedSignature = Microsoft.IdentityModel.JsonWebTokens.JwtTokenUtilities.CreateEncodedSignature(string.Concat(
                resourceToken.EncodedHeader, ".", resourceToken.EncodedPayload),
                new SigningCredentials(new ECDsaSecurityKey(KeyPair.EcdsaKey)
                {
                    KeyId = Guid.NewGuid().ToString()
                }, SecurityAlgorithms.EcdsaSha256
            ));

            var resourceTokenString = string.Concat(
                resourceToken.EncodedHeader, ".", resourceToken.EncodedPayload, ".", encodedSignature);

            //napraviti http request prema poslužitelju resursa
            using (var request = new HttpRequestMessage(HttpMethod.Get, "https://resouce.example.com/resource"))
            {
                request.Headers.Add("DPoP", resourceTokenString);
                //u header još dodati host i conent-type
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", accessToken);
                using (var response = await httpClient.SendAsync(request))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                    }

                    accessToken = await response.Content.ReadAsStringAsync();
                }
            };
        }

        public async Task GetAccessTokenV2() 
        {
            var jwk = new JsonWebKey
            {
                Kty = "EC",
                X = Base64UrlEncoder.Encode(KeyPair.PublicKey.X),
                Y = Base64UrlEncoder.Encode(KeyPair.PublicKey.Y),
                Crv = "P-256"
            };

            var jwtHeader = new JwtHeader()
                {
                    { JwtHeaderParameterNames.Typ, "dpop+jwt" },
                    { JwtHeaderParameterNames.Alg, "ES256" },
                    { JwtHeaderParameterNames.Jwk, JsonSerializer.Serialize(jwk) }
                };

            var payload = new JwtPayload();

            var claims = new[]
            {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("htm", "POST"), 
                    //htu
                    new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                    //ath, nonce
            };
            payload.AddClaims(claims);

            var token = new JwtSecurityToken(jwtHeader, payload);

            var tokenString = string.Concat(token.Header.Base64UrlEncode(), ".", token.EncodedPayload, ".");

            //sign token
            var encodedSignature = Microsoft.IdentityModel.JsonWebTokens.JwtTokenUtilities.CreateEncodedSignature(string.Concat(
                token.EncodedHeader, ".", token.EncodedPayload),
                new SigningCredentials(new ECDsaSecurityKey(KeyPair.EcdsaKey)
                {
                    KeyId = Guid.NewGuid().ToString()
                }, SecurityAlgorithms.EcdsaSha256
            ));

            var resourceTokenString = string.Concat(
                token.EncodedHeader, ".", token.EncodedPayload, ".", encodedSignature);
        }
    }
}
