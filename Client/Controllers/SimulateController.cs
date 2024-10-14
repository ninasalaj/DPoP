using Microsoft.AspNetCore.Mvc;

namespace Client.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SimulateController : ControllerBase
    {
        private readonly TokenGenerator _tokenGenerator;
        private readonly string authorizationServerBaseUrl = "https://localhost:7274/";
        private readonly string resourceServerBaseUrl = "https://localhost:7095/";
        public SimulateController(TokenGenerator tokenGenerator)
        {
            _tokenGenerator = tokenGenerator;
        }

        [HttpGet(Name = "Simulate")]
        public async Task<IActionResult> Simulate()
        {
            //create DPoP proof token for token request
            var dpopProofTokenForTokenRequest = _tokenGenerator.GenerateProofToken(Request.Method, $"{authorizationServerBaseUrl}token/token");

            //get access token from AuthorizationServer
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"{authorizationServerBaseUrl}token/token");
            request.Headers.Add("DPoP", dpopProofTokenForTokenRequest);
            var accessToken = await SendRequest(request);

            //create DPoP proof token for resource request
            var accessTokenProof = _tokenGenerator.GenerateDpopProofBindedToAccessToken(HttpMethod.Get.ToString(), $"{resourceServerBaseUrl}resource/resource", accessToken);
            
            //get resource from ResourceServer 
            HttpRequestMessage requestToResourceServer = new HttpRequestMessage(HttpMethod.Get, $"{resourceServerBaseUrl}resource/resource");
            requestToResourceServer.Headers.Add("DPoP", accessTokenProof);
            requestToResourceServer.Headers.Add("Authorization", accessToken);
            string responseFromResourceServer = await SendRequest(requestToResourceServer);
            
            return Ok(responseFromResourceServer);
        }

        private async Task<string> SendRequest(HttpRequestMessage request)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                throw new Exception("Sending request failed.");
            }
        }
    }
}
