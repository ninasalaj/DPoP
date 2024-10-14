using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;

namespace DPoP_V2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly DPoPAccessTokenService _tokenService;
        private readonly DPoPProtectedResourceRequestService _requestService;
        private readonly DPopHeaderService _dpopHeaderService;
        private readonly ClientService _clientService;

        public TestController (DPoPAccessTokenService tokenService, 
            DPoPProtectedResourceRequestService requestService, 
            DPopHeaderService dpop, 
            ClientService clientService)
        {
            _tokenService = tokenService;
            _requestService = requestService;
            _dpopHeaderService = dpop;
            _clientService = clientService;
        }

        [HttpPost("TestAll")]
        public IActionResult TestAll()
        {
            return Ok(_clientService.GetAccessToken());
        }

        [HttpPost("CreateDPoPRequest")]
        public IActionResult CreateDPoPRequest()
        {
            return Ok(_tokenService.CreateDPoPRequest());
        }

        [HttpPost("CreateAccessToken")]
        public IActionResult CreateAccessToken() 
        {
            var jwk = new JsonWebKey
            {
                Kty = "EC",
                X = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                Y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
                Crv = "P-256"
            };
            var testHeader = new JwtHeader() {
                { JwtHeaderParameterNames.Typ, "dpop+jwt" },
                { JwtHeaderParameterNames.Alg, "ES256" },
                { JwtHeaderParameterNames.Jwk, JsonSerializer.Serialize(jwk) }
            };
            var response = _tokenService.CreateAccessToken("username", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", testHeader);
            return Ok(response.tokenString);
        }

        [HttpPost("CreateRequest")]
        public IActionResult CreateRequest()
        {
            return Ok(_requestService.CreateRequest());
        }
    }
}
