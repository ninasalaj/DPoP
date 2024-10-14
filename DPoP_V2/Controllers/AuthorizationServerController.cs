using Microsoft.AspNetCore.Mvc;

namespace DPoP_V2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthorizationServerController : ControllerBase
    {
        private readonly AuthorizationServerService _service;

        public AuthorizationServerController(AuthorizationServerService service) 
        { 
            _service = service;
        }

        [HttpPost("GetAccessToken")]
        public IActionResult GetAccessToken()
        {
            //DPoP bi trebao biti case insensitive  
            if (Request.Headers.TryGetValue("DPoP", out var dpopHeader))
            {
                // Ako postoji, pretvorite u string
                string dpopToken = dpopHeader.ToString();
                //potrebno je zatim validirati dpop

                var accessToken = _service.CreateAccessToken(dpopToken);

                // Daljnja obrada
                return Ok(accessToken.tokenString);
            }

            // Ako zaglavlje ne postoji, vratite loš zahtjev
            return BadRequest("DPoP header is missing");
        }
    }
}
