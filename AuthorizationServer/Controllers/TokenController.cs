using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly TokenGenerator _tokenGenerator;
        private readonly ProofValidator _proofValidator;
        public TokenController(TokenGenerator tokenGenerator, ProofValidator proofValidator)
        {
            _tokenGenerator = tokenGenerator;
            _proofValidator = proofValidator;
        }

        [HttpGet("token")]
        public IActionResult IssueToken([FromHeader(Name = "DPoP")] string dpopProof)
        {
            if (_proofValidator.VerifyDpopProof(dpopProof, Request.Method, Request.GetDisplayUrl()))
            {
                var token = _tokenGenerator.CreateAccessToken(dpopProof);
                return Ok(token);
            }
            return Unauthorized();
        }
    }
}
