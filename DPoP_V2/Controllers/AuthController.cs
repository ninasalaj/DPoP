using Microsoft.AspNetCore.Mvc;

namespace DPoP_V2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        public AuthController()
        {
        }

        [HttpPost("GetDPoP")]
        public IActionResult GetDPoP()
        {
            return Ok();
        }
    }
}
