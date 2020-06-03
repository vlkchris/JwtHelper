using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Xunit;

namespace IssueReport
{
    public class JwtHelperTests
    {
        [Fact]
        public void FailsWithSameKey()
        {
            RSA apprsa = RSA.Create();
            var securityKey = new RsaSecurityKey(apprsa);
            var pubkey = apprsa.ExportSubjectPublicKeyInfo();
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            var jwtheader = new JwtHeader(credentials);
            var jwtpayload = new JwtPayload
            {
                { "someclaim", "some value" },
            };
            var secToken = new JwtSecurityToken(jwtheader, jwtpayload);
            var handler = new JwtSecurityTokenHandler();
            var tokenString = handler.WriteToken(secToken);

            var helper = new JwtHelper();

            //ok
            helper.ValidateToken(tokenString, pubkey);

            // throws exception
            var result = Assert.Throws<SecurityTokenInvalidSignatureException>(()=> helper.ValidateToken(tokenString, pubkey));
            Assert.Contains("ObjectDisposedException", result.Message);

            // ok
            helper.ValidateToken(tokenString, pubkey);
        }

        [Fact]
        public void OkWithDifferentKey()
        {
            RSA apprsa = RSA.Create();
            var securityKey = new RsaSecurityKey(apprsa);
            var pubkey = apprsa.ExportSubjectPublicKeyInfo();
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            var jwtheader = new JwtHeader(credentials);
            var jwtpayload = new JwtPayload
            {
                { "someclaim", "some value" },
            };
            var secToken = new JwtSecurityToken(jwtheader, jwtpayload);
            var handler = new JwtSecurityTokenHandler();
            var tokenString = handler.WriteToken(secToken);

            var helper = new JwtHelper();

            // ok
            helper.ValidateToken(tokenString, pubkey);

            // ok with different key
            helper.ValidateToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDaGFsbGVuZ2VSZXNwb25zZSI6InhoeE1iSEJ5NWZRUEtYQ1lKZmxkd3oydlhUUjR6UWVzOGdNTGtMWE1hVTZEMnN3dFZLcnB0ZGVxYWhnbGlOVXkiLCJleHAiOjE1OTEwODk4MTguOTc2ODgzNn0.O0paZqAavS7ml9P6ztAs3Crh0wEjV3CbU64hoPagZ_YkbD5_wDb-dr2dErvq4K-JJ83msnnh4MFlaZgFETSOuMXX4QLulz6KJ7p4tWUobn0uum8ko0CQ0u5gxy6qrdcXzNwPyUd2q6eODFjKD1C9oVhm-RqxzL6UeleqbofgMI-l-kQ7vSKN2PvZBFw5fZ6HYMPnSykqgtOTaMS6X2DrUdZAZmkkmDUrpGHhkCB8gBK1goSgwxeB7k9iAi9HBqw_3GZw_cX1cZurIl7xeu7fnXe3DsW6ZSmwsuJThoXACcDfASEFDwWRSfwYK2BmCJUhITt2Pim4CGFPJHF1vxOcYA",
                Convert.FromBase64String("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwzVIgry+QCO3TsOmQcB3xYfCj/Eb+JOVOObm/DMNSdRpIu9mp5vxtXFaMqb4WzccDLAY2xDkV+QEZAnUWEXGQwNL9Mcl6IUVYoalCwbPMwQpcGFqLhB1fhkXgoWTtWnYasOprEPg/xHV6Ac0GiLl0zEseb1pUuDO6VtKth7M/+eW18AsGzuI5Wc4Lb1M7XxQEmvlvLs3YwzNZK7ITp0IO5d5qS+0cvUKiUKo/eeC2nTWtAGk/9kQRehlX6XmUdKrR50uT1pn6Sj0Hod1n7X5YLjYp/cSgkEMrQ2ALTNkrm1/kf7SjeLyIAhUpGC5ahMPzyLcBqr6R5UpcHTc6g4QZQIDAQAB"));

            // same key as before throws exception
            var result = Assert.Throws<SecurityTokenInvalidSignatureException>(()=>helper.ValidateToken(tokenString, pubkey));
            Assert.Contains("ObjectDisposedException", result.Message);
        }
    }
}
