using System.Text.Json;
using JWTwithDPoP.CommonInterface;
using JWTwithDPoP.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTwithDPoP.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IJwtService _jwtService;
        private const string DPOP_NONCE_HEADER = "DPoP-Nonce";

        public AuthController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User model, [FromHeader(Name = "DPoP")] string dpopToken)
        {
            // Validate user credentials (replace with your actual authentication logic)


            if (string.IsNullOrEmpty(dpopToken))
                return Unauthorized(new { message = "DPoP proof is required" });

            var dpopProof = new DPoPProof { RawToken = dpopToken };

            if (!_jwtService.ValidateDPoPProof(dpopProof))
                return Unauthorized(new { message = "Invalid DPoP proof" });

            var user = ValidateUserCredentials(model);

            if (user == null)
                return Unauthorized();

            var token = _jwtService.GenerateToken(user, dpopProof);
            Response.Headers.Add(DPOP_NONCE_HEADER, _jwtService.GenerateNonce());

            return Ok(new { token });
        }

        private User ValidateUserCredentials(User model)
        {
            // Replace with your actual user validation logic
            return new User
            {
                Username = model.Username,
                Password = model.Password,
                Role = "User"
            };
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("Device")]
        public async Task<IActionResult> GetDevice([FromHeader(Name = "DPoP")] string dpopToken)
        {
            try
            {
                if (string.IsNullOrEmpty(dpopToken))
                    return Unauthorized(new { message = "DPoP proof is required" });

                var accessToken = HttpContext.Request.Headers["Authorization"]
                    .FirstOrDefault()?.Split(" ").Last();

                if (string.IsNullOrEmpty(accessToken))
                    return Unauthorized(new { message = "Access token is required" });

                var dpopProof = new DPoPProof { RawToken = dpopToken };

                if (!_jwtService.ValidateDPoPProof(dpopProof, accessToken))
                    return Unauthorized(new { message = "Invalid DPoP proof" });

                // Add new nonce for subsequent requests
                Response.Headers.Add(DPOP_NONCE_HEADER, _jwtService.GenerateNonce());

                var devices = new List<Device>
            {
                new Device { DeviceId = 1, DeviceName = "Device 1", DeviceType = "IPCamera" },
                new Device { DeviceId = 2, DeviceName = "Device 2", DeviceType = "IPCamera" }
            };

                return Ok(devices);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = ex.Message });
            }

        }
    }
}
