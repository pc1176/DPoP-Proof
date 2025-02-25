using JWTwithDPoP.CommonInterface;
using JWTwithDPoP.Model;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JWTwithDPoP.Services
{
    public class JwtService : IJwtService
    {
        private readonly JwtSettings _jwtSettings;
        private static readonly ConcurrentDictionary<string, DateTime> _usedJtis = new();
        private static readonly ConcurrentDictionary<string, string> _activeNonces = new();
        private const int NONCE_LIFETIME_MINUTES = 5;


        public JwtService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public string GenerateToken(User user, DPoPProof dpopProof)
        {
            //if (!ValidateDPoPProof(dpopProof))
            //{
            //    throw new SecurityException("Invalid DPoP proof");
            //}
            //jkt = jktHash;

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("cnf", JsonSerializer.Serialize(new {
                jwk = dpopProof.DecodedHeader.Jwk
            }))
        };

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_jwtSettings.ExpirationInMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        //public bool ValidateToken(string token, DPoPProof dpopProof)
        //{
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);

        //    try
        //    {
        //        var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        //        {
        //            ValidateIssuerSigningKey = true,
        //            IssuerSigningKey = new SymmetricSecurityKey(key),
        //            ValidateIssuer = true,
        //            ValidIssuer = _jwtSettings.Issuer,
        //            ValidateAudience = true,
        //            ValidAudience = _jwtSettings.Audience,
        //            ValidateLifetime = true,
        //            ClockSkew = TimeSpan.Zero
        //        }, out var validatedToken);

        //        if (dpopProof == null || string.IsNullOrEmpty(dpopProof.PublicKey))
        //        {
        //            return false;
        //        }

        //        using var sha256 = SHA256.Create();
        //        var jktHash = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(dpopProof.PublicKey)));
        //        var jwtSecurityToken = validatedToken as JwtSecurityToken;
        //        var jktClaim = jwtSecurityToken?.Claims.FirstOrDefault(c => c.Type == "jkt")?.Value;

        //        return jktClaim == jktHash;
        //    }
        //    catch
        //    {
        //        return false;
        //    }
        //}

        public bool ValidateDPoPProof(DPoPProof proof, string accessToken = null)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(proof.RawToken);

                // Decode and populate the proof object
                proof.DecodedHeader = JsonSerializer.Deserialize<DPoPProof.Header>(
                    Base64UrlDecode(proof.RawToken.Split('.')[0]));
                proof.DecodedPayload = JsonSerializer.Deserialize<DPoPProof.Payload>(
                    Base64UrlDecode(proof.RawToken.Split('.')[1]));

                // 1. Validate JOSE header
                if (!ValidateHeader(proof.DecodedHeader))
                    return false;

                // 2. Validate signature using public key from JWK
                if (!ValidateSignature(proof))
                    return false;

                // 3. Validate required claims
                if (!ValidateRequiredClaims(proof.DecodedPayload))
                    return false;

                // 4. Validate JTI uniqueness and timestamp
                if (!ValidateJtiAndTimestamp(proof.DecodedPayload))
                    return false;

                // 5. If access token is present, validate ATH claim
                if (accessToken != null && !ValidateAccessTokenHash(proof.DecodedPayload, accessToken))
                    return false;

                // 6. Validate nonce if present
                if (proof.DecodedPayload.Nonce != null && !ValidateNonce(proof.DecodedPayload.Nonce))
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DPoP validation error: {ex.Message}");
                return false;
            }
        }

        private bool ValidateHeader(DPoPProof.Header header)
        {
            return header.Typ == "dpop+jwt" &&
                   header.Alg == "RSA256" &&
                   header.Jwk?.Kty == "RSA" &&
                   !string.IsNullOrEmpty(header.Jwk.N) &&
                   !string.IsNullOrEmpty(header.Jwk.E);
        }

        private bool ValidateSignature(DPoPProof proof)
        {
            try
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Base64UrlDecode(proof.DecodedHeader.Jwk.N),
                    Exponent = Base64UrlDecode(proof.DecodedHeader.Jwk.E)
                });

                var parts = proof.RawToken.Split('.');
                var signedData = $"{parts[0]}.{parts[1]}";
                var signature = Base64UrlDecode(parts[2]);

                return rsa.VerifyData(
                    Encoding.UTF8.GetBytes(signedData),
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        public string GenerateNonce()
        {
            var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            _activeNonces.TryAdd(nonce, DateTime.UtcNow.ToString("O"));
            return nonce;
        }

        private bool ValidateNonce(string nonce)
        {
            if (_activeNonces.TryGetValue(nonce, out var timestamp))
            {
                if (DateTime.TryParse(timestamp, out var nonceTime))
                {
                    if (DateTime.UtcNow.Subtract(nonceTime).TotalMinutes <= NONCE_LIFETIME_MINUTES)
                    {
                        _activeNonces.TryRemove(nonce, out _);
                        return true;
                    }
                }
            }
            return false;
        }

        private bool ValidateRequiredClaims(DPoPProof.Payload payload)
        {
            // Check if all required claims are present and valid
            if (string.IsNullOrEmpty(payload.Jti) ||
                string.IsNullOrEmpty(payload.Htm) ||
                string.IsNullOrEmpty(payload.Htu) ||
                payload.Iat == 0)
            {
                return false;
            }

            // Validate HTTP method
            if (!new[] { "GET", "POST", "PUT", "DELETE" }.Contains(payload.Htm.ToUpper()))
            {
                return false;
            }

            // Validate URL format
            if (!Uri.TryCreate(payload.Htu, UriKind.Absolute, out _))
            {
                return false;
            }

            return true;
        }

        private bool ValidateJtiAndTimestamp(DPoPProof.Payload payload)
        {
            // Check if JTI has been used before
            if (_usedJtis.TryGetValue(payload.Jti, out var usedTime))
            {
                return false;
            }

            // Validate timestamp (within a reasonable time window, e.g., 3 minutes)
            var proofTime = DateTimeOffset.FromUnixTimeSeconds(payload.Iat);
            var now = DateTimeOffset.UtcNow;
            var timeWindow = TimeSpan.FromMinutes(3);

            if (Math.Abs((now - proofTime).TotalMinutes) > timeWindow.TotalMinutes)
            {
                return false;
            }

            // Store JTI with expiration
            _usedJtis.TryAdd(payload.Jti, DateTime.UtcNow);

            // Cleanup old JTIs (you might want to do this periodically instead)
            var expiredJtis = _usedJtis
                .Where(x => DateTime.UtcNow.Subtract(x.Value) > timeWindow)
                .Select(x => x.Key)
                .ToList();

            foreach (var expiredJti in expiredJtis)
            {
                _usedJtis.TryRemove(expiredJti, out _);
            }

            return true;
        }

        private bool ValidateAccessTokenHash(DPoPProof.Payload payload, string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return false;
            }

            // Calculate access token hash
            using var sha256 = SHA256.Create();
            var tokenHash = sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
            var expectedAth = Base64UrlEncode(tokenHash);

            // Compare with the ath claim
            return payload.Ath == expectedAth;
        }

        private byte[] Base64UrlDecode(string input)
        {
            var base64 = input
                .Replace('-', '+')
                .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }

        private string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }


    }

}
