using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace DPoP_V2
{
    public class DPoPAccessTokenService
    {
        private readonly DPopHeaderService _dPopHeaderService;

        public DPoPAccessTokenService(DPopHeaderService dPopHeaderService) 
        {
            _dPopHeaderService = dPopHeaderService;
        }

        public HttpRequestMessage CreateDPoPRequest() 
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "tokenRequestUri");

            request.Headers.Add("DPoP", _dPopHeaderService.CreateDPoPHeader());
            //u header još dodati host i conent-type

            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_id", "s6BhdRkqt"),
                new KeyValuePair<string, string>("code", "SplxlOBeZQQYbYS6WxSbIA"),
                new KeyValuePair<string, string>("redirect_uri", "https://client.example.com/cb"),
                new KeyValuePair<string, string>("code_verifier", "bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz")
            });

            return request;
        }

        //potrebno implementirati kako se dobije jwkThumbprint iz javnog ključa
        public (JwtSecurityToken token, string tokenString) CreateAccessToken(string username, string jwkThumbprint, JwtHeader dpopHeader) 
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            //var jwk = new JsonWebKey(JoseHeader["jwk"].GetRawText());
            var jwkExtractedValue = dpopHeader["jwk"];
            //var jwkJsonString = JsonSerializer.Serialize(jwkExtractedValue);
            var jwk = new JsonWebKey(jwkExtractedValue as string);
            var thumbprint = jwk.ComputeJwkThumbprint();

            var jktValue = new { jkt = thumbprint };//new { jkt = jwkThumbprint };
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim("cnf", JsonSerializer.Serialize(jktValue)) //vjerojatno treba dorada
                }),
                Expires = DateTime.UtcNow.AddHours(1)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return (token as JwtSecurityToken, tokenHandler.WriteToken(token));
        }
    }
}
