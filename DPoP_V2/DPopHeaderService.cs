using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace DPoP_V2
{
    public class DPopHeaderService
    {
        public string CreateDPoPHeader() 
        {
            //use token68 syntax -> navodno base64 vec odgovara toj sintaksi
            return WriteToken(CreateDPoPProof());
        }

        /// <summary>
        /// returns DPoP proof JWT that is signed with a private key chosen by the client
        /// </summary>
        /// <returns></returns>
        public JwtSecurityToken CreateDPoPProof()
        {
            var token = new JwtSecurityToken(CreateHeader(), CreatePayload());

            //sign the token

            return token;
        }

        /// <summary>
        /// JOSE header
        /// </summary>
        /// <returns></returns>
        public JwtHeader CreateHeader() 
        {
            var ecdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var ecParameters = ecdsaKey.ExportParameters(false); // Export only public key

            var jwk = new JsonWebKey
            {
                Kty = "EC",
                X = Base64UrlEncoder.Encode(ecParameters.Q.X),
                Y = Base64UrlEncoder.Encode(ecParameters.Q.Y),
                Crv = "P-256"
            };

            return new JwtHeader() 
            {
                { JwtHeaderParameterNames.Typ, "dpop+jwt" },
                { JwtHeaderParameterNames.Alg, "ES256" },
                { JwtHeaderParameterNames.Jwk, JsonSerializer.Serialize(jwk) }
            };
        }

        public JwtPayload CreatePayload() 
        {
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
            
            return payload;
        }

        public bool CheckDPoPProof() 
        {
            //check if there is not more than one DPoP HTTP request header field

            //check if the value of DPoP filed value is single and well-formed JWT

            //check if all required claims (header: typ, alg, jwk, payload: jti, htm, htu, iat) are contained in the JWT 

            //check if the typ JOSE header parameter has the value of dpop+jwt

            //check if the alg JOSE header parameter indicates a registered asymmetric digital signature algorithm

            //check if the JWT signature verifes with the public key contained in the jwk JOSE Header Parameter

            //check if the jwk JOSE Header Parameter does NOT contain a private key

            //check if the htm claim matches the HTTP method of the current request

            //check if the htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts

            //if the server provided a nonce value to the client, check if the nonce claim matches the server-provided nonce value

            //check if the creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window

            //If presented to a protected resource in conjunction with an access token
                //ensure that the value of the ath claim equals the hash of that access token
                //confirm that the public key to which the access token is bound matches the public key from the DPoP proof
            
            //to reduce the likelihood of false negatives, servers should employ syntaxx-based normalization and scheme-based normalization before comparing the htu claim
            return true;
        }

        public string WriteToken(JwtSecurityToken jwtToken)
        {
            if (jwtToken == null)
                throw new ArgumentNullException("Token cannot be null");

            var encodedPayload = jwtToken.EncodedPayload;
            var encodedSignature = string.Empty;
            var encodedHeader = string.Empty;
            if (jwtToken.InnerToken != null)
            {
                if (jwtToken.SigningCredentials != null)
                    throw new SecurityTokenEncryptionFailedException();

                if (jwtToken.InnerToken.Header.EncryptingCredentials != null)
                    throw new SecurityTokenEncryptionFailedException();

                if (jwtToken.Header.EncryptingCredentials == null)
                    throw new SecurityTokenEncryptionFailedException();

                //if (jwtToken.InnerToken.SigningCredentials != null)
                //    encodedSignature = JwtTokenUtilities.CreateEncodedSignature(string.Concat(jwtToken.InnerToken.EncodedHeader, ".", jwtToken.EncodedPayload), jwtToken.InnerToken.SigningCredentials);

                return EncryptToken(
                    new JwtSecurityToken(
                        jwtToken.InnerToken.Header,
                        jwtToken.InnerToken.Payload,
                        jwtToken.InnerToken.EncodedHeader,
                        encodedPayload, encodedSignature),
                    jwtToken.EncryptingCredentials,
                    jwtToken.InnerToken.Header.Typ,
                    null).RawData;
            }

            // if EncryptingCredentials isn't set, then we need to create JWE
            // first create a new header with the SigningCredentials, Create a JWS then wrap it in a JWE
            var header = jwtToken.EncryptingCredentials == null ? jwtToken.Header : new JwtHeader(jwtToken.SigningCredentials);
            encodedHeader = header.Base64UrlEncode();
            //if (jwtToken.SigningCredentials != null)
            //    encodedSignature = JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload), jwtToken.SigningCredentials);

            //if (jwtToken.EncryptingCredentials != null)
            //    return EncryptToken(
            //        new JwtSecurityToken(
            //            header,
            //            jwtToken.Payload,
            //            encodedHeader,
            //            encodedPayload,
            //            encodedSignature),
            //        jwtToken.EncryptingCredentials,
            //        jwtToken.Header.Typ,
            //        null).RawData;
            //else
                return string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        }

        private JwtSecurityToken EncryptToken(
            JwtSecurityToken innerJwt,
            EncryptingCredentials encryptingCredentials,
            string tokenType,
            IDictionary<string, object> additionalHeaderClaims)
        {
            //if (encryptingCredentials == null)
            //    throw new ArgumentNullException();

            //var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            //if (cryptoProviderFactory == null)
            //    throw new ArgumentException();

            //SecurityKey securityKey = JwtTokenUtilities.GetSecurityKey(encryptingCredentials, cryptoProviderFactory, additionalHeaderClaims, out byte[] wrappedKey);
            //using (AuthenticatedEncryptionProvider encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(securityKey, encryptingCredentials.Enc))
            //{
            //    if (encryptionProvider == null)
            //        throw new SecurityTokenEncryptionFailedException();

            //    try
            //    {
            //        var header = new JwtHeader(encryptingCredentials, OutboundAlgorithmMap, tokenType, additionalHeaderClaims);
            //        var encodedHeader = header.Base64UrlEncode();
            //        AuthenticatedEncryptionResult encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(innerJwt.RawData), Encoding.ASCII.GetBytes(encodedHeader));
            //        return JwtConstants.DirectKeyUseAlg.Equals(encryptingCredentials.Alg) ?
            //            new JwtSecurityToken(
            //                header,
            //                innerJwt,
            //                encodedHeader,
            //                string.Empty,
            //                Base64UrlEncoder.Encode(encryptionResult.IV),
            //                Base64UrlEncoder.Encode(encryptionResult.Ciphertext),
            //                Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag)) :
            //            new JwtSecurityToken(
            //                header,
            //                innerJwt,
            //                encodedHeader,
            //                Base64UrlEncoder.Encode(wrappedKey),
            //                Base64UrlEncoder.Encode(encryptionResult.IV),
            //                Base64UrlEncoder.Encode(encryptionResult.Ciphertext),
            //                Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
            //    }
            //    catch (Exception ex)
            //    {
            //        throw new SecurityTokenEncryptionFailedException(ex.Message);
            //    }
            //}

            return null;
        }
    }
}
