using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using JWTClient.Model;

namespace JWTClient.Services
{
    public class ApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private string _token;
        private RSA _rsaKey;
        private string _currentNonce;

        public ApiClient(string baseUrl)
        {
            _httpClient = new HttpClient();
            _baseUrl = baseUrl;
            _rsaKey = RSA.Create(2048);
        }

        public async Task<bool> LoginAsync(string username, string password)
        {
            try
            {
                var loginData = new { Username = username, Password = password, Role = "string" };

                // Generate DPoP proof for login
                var dpopProof = GenerateDPoPProof("POST", $"{_baseUrl}/api/Auth/login");

                var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/api/Auth/login");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Add("DPoP", dpopProof.EncodedToken);
                request.Content = JsonContent.Create(loginData);

                var response = await _httpClient.SendAsync(request);

                // Check for DPoP-Nonce header in response
                if (response.Headers.TryGetValues("DPoP-Nonce", out var nonceValues))
                {
                    _currentNonce = nonceValues.FirstOrDefault();
                }

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<TokenResponse>();
                    _token = result.Token;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Login error: {ex.Message}");
                return false;
            }
        }
        public async Task<List<Device>> GetProductsAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(_token))
                    throw new InvalidOperationException("Not authenticated");

                // Generate DPoP proof for the request including access token hash
                var dpopProof = GenerateDPoPProof("GET", $"{_baseUrl}/api/Auth/Device", _token);

                var request = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/api/Auth/Device");
                request.Headers.Add("DPoP", dpopProof.EncodedToken);
                request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", _token);

                var response = await _httpClient.SendAsync(request);

                // Update nonce if provided
                if (response.Headers.TryGetValues("DPoP-Nonce", out var nonceValues))
                {
                    _currentNonce = nonceValues.FirstOrDefault();
                }

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadFromJsonAsync<List<Device>>();
                }
                else{
                    return new List<Device>();
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"GetProducts error: {ex.Message}");
                throw;
            }
        }

        private DPoPProof GenerateDPoPProof(string httpMethod, string url, string accessToken = null)
        {
            var header = new DPoPProof.Header
            {
                Typ = "dpop+jwt",
                Alg = "RSA256",
                Jwk = new DPoPProof.JwkData
                {
                    N = Base64UrlEncode(_rsaKey.ExportParameters(false).Modulus),
                    E = Base64UrlEncode(_rsaKey.ExportParameters(false).Exponent)
                }
            };

            var payload = new DPoPProof.Payload
            {
                Jti = Guid.NewGuid().ToString(),
                Htm = httpMethod,
                Htu = url,
                Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            // Add access token hash if token is provided
            if (!string.IsNullOrEmpty(accessToken))
            {
                using var sha256 = SHA256.Create();
                var tokenHash = sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
                payload.Ath = Base64UrlEncode(tokenHash);
            }

            // Add nonce if available
            if (!string.IsNullOrEmpty(_currentNonce))
            {
                payload.Nonce = _currentNonce;
            }

            var dpopProof = new DPoPProof { EncodedToken = CreateJwt(header, payload) };
            return dpopProof;
        }

        private string CreateJwt(DPoPProof.Header header, DPoPProof.Payload payload)
        {
            var headerJson = JsonSerializer.Serialize(header);
            var payloadJson = JsonSerializer.Serialize(payload);

            var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

            var unsignedToken = $"{headerBase64}.{payloadBase64}";
            var signature = SignData(unsignedToken);

            return $"{unsignedToken}.{signature}";
        }

        private string SignData(string data)
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var signatureBytes = _rsaKey.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Base64UrlEncode(signatureBytes);
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

