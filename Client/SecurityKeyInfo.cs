using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Client
{
    public static class SecurityKeyInfo
    {
        public static SecurityKey Key { get; set; } = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));
        public static string SigningAlgorithm { get; set; } = "ES256";
        public static JsonWebKey Jwk { get; set; } = new JsonWebKey()
        {
            Kty = "EC",
            X = Base64UrlEncoder.Encode((Key as ECDsaSecurityKey).ECDsa.ExportParameters(false).Q.X),
            Y = Base64UrlEncoder.Encode((Key as ECDsaSecurityKey).ECDsa.ExportParameters(false).Q.Y),
            Crv = "P-256"
        };
    }
}
