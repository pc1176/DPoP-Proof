using JWTwithDPoP.Model;
using System.Security.Claims;

namespace JWTwithDPoP.CommonInterface
{
    public interface IJwtService
    {
        string GenerateToken(User user, DPoPProof dpopProof);
        //bool ValidateToken(string token, DPoPProof dpopProof);

        bool ValidateDPoPProof(DPoPProof proof, string accessToken = null);

        string GenerateNonce();
    }
}
