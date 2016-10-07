using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SampleMvcApp.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                var identity = User.Identity as ClaimsIdentity;
                ViewBag.IdToken = identity?.FindFirst("id_token")?.Value;
            }
            return this.View();
        }

        [Authorize(ActiveAuthenticationSchemes = "Auth0")]
        public IActionResult Profile()
        {
            return this.View(this.User.Claims);
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
