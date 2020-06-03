using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace IssueReport
{
    public class JwtHelper
    {
        public void ValidateToken(string token, byte[] publicKey)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKey, out int bytesRead);

            SecurityKey key = new RsaSecurityKey(rsa);

            var handler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateLifetime = false,
                ValidateAudience = false, // Because there is no audience in the generated token
                ValidateIssuer = false,   // Because there is no issuer in the generated token
                IssuerSigningKey = key
            };

            IdentityModelEventSource.ShowPII = true;

            handler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

        }
    }
}
