using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SampleMvcApp.Code;

namespace SampleMvcApp.Controllers
{
    public class AccountController : Controller
    {

        private readonly IOptions<OpenIdConnectOptions> _options;

        public AccountController(IOptions<OpenIdConnectOptions> options)
        {
            _options = options;
        }

        public IActionResult Login(string returnUrl = null)
        {
            var lockContext = HttpContext.GenerateLockContext(_options.Value, returnUrl);
            return View(lockContext);
        }

        public async Task<IActionResult> Logout(string returnUrl)
        {

            // Sign the user out of the authentication middleware (i.e. it will clear the Auth cookie)
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                await HttpContext.Authentication.SignOutAsync("Auth0");
                await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            // Redirect the user to the home page after signing out
            return RedirectToAction("Index", "Home");
        }

    }
}
