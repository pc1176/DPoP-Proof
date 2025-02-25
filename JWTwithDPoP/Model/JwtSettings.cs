namespace JWTwithDPoP.Model
{
    public class JwtSettings
    {
        public string SecretKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        
        public bool RequireDPoP { get; set; }
        public int DPoPNonceLifetimeSeconds { get; set; }
        public int ExpirationInMinutes { get; set; }
    }

    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }

    public class Device
    {
        public long DeviceId { get; set; }
        public string DeviceName { get; set; }

        public string DeviceType { get; set; }
    }

    public class DPoPProof
    {
        // JOSE Header
        public class Header
        {
            public string Typ { get; set; } = "dpop+jwt";
            public string Alg { get; set; } = "RS256";
            public JwkData Jwk { get; set; }
        }

        // JWK Data
        public class JwkData
        {
            public string Kty { get; set; } = "RSA";
            public string N { get; set; }  // modulus
            public string E { get; set; }  // exponent
        }

        // Payload
        public class Payload
        {
            public string Jti { get; set; }
            public string Htm { get; set; }
            public string Htu { get; set; }
            public long Iat { get; set; }
            public string Ath { get; set; }  // Access token hash when needed
            public string Nonce { get; set; } // Server provided nonce when needed
        }

        //public string EncodedToken { get; set; }
        public string RawToken { get; set; }
        public Header DecodedHeader { get; set; }
        public Payload DecodedPayload { get; set; }
    }

}
