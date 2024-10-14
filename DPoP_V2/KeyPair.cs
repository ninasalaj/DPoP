using System.Security.Cryptography;

namespace DPoP_V2
{
    public static class KeyPair
    {
        public static ECDsa EcdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public static ECParameters EcdsaParameters = EcdsaKey.ExportParameters(true);
        public static byte[] PrivateKey = EcdsaParameters.D;
        public static ECPoint PublicKey = EcdsaParameters.Q;
    }
}