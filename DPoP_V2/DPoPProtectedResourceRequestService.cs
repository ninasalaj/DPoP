using System.Net.Http.Headers;

namespace DPoP_V2
{
    public class DPoPProtectedResourceRequestService
    {
        private readonly DPopHeaderService dPopHeaderService;
        public HttpRequestMessage CreateRequest() 
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "protectedresource");
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU");
            request.Headers.Add("DPoP", dPopHeaderService.CreateDPoPHeader());

            return request;
        }
    }
}
