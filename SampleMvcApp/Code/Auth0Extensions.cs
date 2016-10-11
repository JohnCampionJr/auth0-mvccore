using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleMvcApp.Code
{
    public static class Auth0Extensions
    {
        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
        private const string CorrelationPrefix = ".AspNetCore.Correlation.";
        private const string CorrelationProperty = ".xsrf";
        private const string CorrelationMarker = "N";
        private const string NonceProperty = "N";

        private static string BuildRedirectUri(HttpRequest request, PathString redirectPath)
        {
            return request.Scheme + "://" + request.Host + request.PathBase + redirectPath;
        }

        private static void GenerateCorrelationId(HttpContext httpContext, OpenIdConnectOptions options, AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            var bytes = new byte[32];
            CryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = httpContext.Request.IsHttps,
                Expires = properties.ExpiresUtc
            };

            properties.Items[CorrelationProperty] = correlationId;

            var cookieName = CorrelationPrefix + options.AuthenticationScheme + "." + correlationId;

            httpContext.Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
        }

        public static LockContext GenerateLockContext(this HttpContext httpContext, OpenIdConnectOptions options, string returnUrl = null)
        {

            LockContext lockContext = new LockContext { ClientId = options.ClientId };

            // retrieve the domain from the authority
            Uri authorityUri;
            if (Uri.TryCreate(options.Authority, UriKind.Absolute, out authorityUri))
            {
                lockContext.Domain = authorityUri.Host;
            }

            // Set the redirect
            string callbackUrl = BuildRedirectUri(httpContext.Request, options.CallbackPath);
            lockContext.CallbackUrl = callbackUrl;

            // Add the nonce.
            var nonce = options.ProtocolValidator.GenerateNonce();
            httpContext.Response.Cookies.Append(
                OpenIdConnectDefaults.CookieNoncePrefix + options.StringDataFormat.Protect(nonce),
                NonceProperty,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = httpContext.Request.IsHttps,
                    Expires = DateTime.UtcNow + options.ProtocolValidator.NonceLifetime
                });
            lockContext.Nonce = nonce;

            // Since we are handling the 1st leg of the Auth (redirecting to /authorize), we need to generate the correlation ID so the 
            // OAuth middleware can validate it correctly once it picks up from the 2nd leg (receiving the code)
            var properties = new AuthenticationProperties()
            {
                ExpiresUtc = options.SystemClock.UtcNow.Add(options.RemoteAuthenticationTimeout),
                RedirectUri = returnUrl ?? "/"
            };
            properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey] = callbackUrl;
            GenerateCorrelationId(httpContext, options, properties);

            // Generate State
            lockContext.State = Uri.EscapeDataString(options.StateDataFormat.Protect(properties));

            // return the Lock context
            return lockContext;
        }

        public static void AddAuth0OpenId(this IServiceCollection services, IConfigurationRoot configuration,
            bool saveTokens = false)
        {

            // Add authentication services
            services.AddAuthentication(
                options => options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

            // Configure OIDC
            services.Configure<OpenIdConnectOptions>(options => {
                // Specify Authentication Scheme
                options.AuthenticationScheme = "Auth0";

                // Set the authority to your Auth0 domain
                options.Authority = $"https://{configuration["auth0:domain"]}";

                // Configure the Auth0 Client ID and Client Secret
                options.ClientId = configuration["auth0:clientId"];
                options.ClientSecret = configuration["auth0:clientSecret"];

                // Do not automatically authenticate and challenge
                options.AutomaticAuthenticate = false;
                options.AutomaticChallenge = false;

                // Set response type to code
                options.ResponseType = "code";

                // Set the callback path, so Auth0 will call back to http://localhost:5000/signin-auth0 
                // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard 
                options.CallbackPath = new PathString(configuration["auth0:callbackUrl"]);

                // Configure the Claims Issuer to be Auth0
                options.ClaimsIssuer = "Auth0";

                options.SaveTokens = saveTokens;

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        context.Response.Redirect(new PathString("/Account/Login"));
                        context.HandleResponse();

                        return Task.FromResult(0);
                    },
                    OnTicketReceived = context => {
                        // Get the ClaimsIdentity
                        var identity = context.Principal.Identity as ClaimsIdentity;
                        if (identity != null)
                        {
                            // Add the Name ClaimType. This is required if we want User.Identity.Name to actually return something!
                            if (!context.Principal.HasClaim(c => c.Type == ClaimTypes.Name) &&
                                identity.HasClaim(c => c.Type == "name"))
                                identity.AddClaim(new Claim(ClaimTypes.Name, identity.FindFirst("name").Value));

                            // Check if token names are stored in Properties
                            if (context.Properties.Items.ContainsKey(".TokenNames"))
                            {
                                // Token names a semicolon separated
                                string[] tokenNames = context.Properties.Items[".TokenNames"].Split(';');

                                // Add each token value as Claim
                                foreach (var tokenName in tokenNames)
                                {
                                    // Tokens are stored in a Dictionary with the Key ".Token.<token name>"
                                    string tokenValue = context.Properties.Items[$".Token.{tokenName}"];

                                    identity.AddClaim(new Claim(tokenName, tokenValue));
                                }
                            }
                        }

                        return Task.FromResult(0);
                    }
                };
            });

        }

        public static IApplicationBuilder UseAuth0CookieAuthentication(this IApplicationBuilder app, OpenIdConnectOptions options)
        {
            // Add the cookie middleware
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                SlidingExpiration = true,
                ExpireTimeSpan = TimeSpan.FromHours(1)
            });

            // Add the OIDC middleware
            app.UseOpenIdConnectAuthentication(options);

            return app;

        }

        public static IApplicationBuilder UseAuth0BearerAuthentication(this IApplicationBuilder app, IConfigurationRoot configuration)
        {
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                Audience = configuration["auth0:clientId"],
                Authority = $"https://{configuration["auth0:domain"]}/",
                AuthenticationScheme = "Bearer",
                AutomaticAuthenticate = false,
                AutomaticChallenge = false,
                Events = new JwtBearerEvents
                {
                    OnTokenValidated = context => {
                        // Get the ClaimsIdentity
                        var claimsIdentity = context.Ticket.Principal.Identity as ClaimsIdentity;

                        if (claimsIdentity != null)
                        {
                            // Add the Name ClaimType. This is required if we want User.Identity.Name to actually return something!
                            if (!context.Ticket.Principal.HasClaim(c => c.Type == ClaimTypes.Name) &&
                                claimsIdentity.HasClaim(c => c.Type == "name"))
                                claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, claimsIdentity.FindFirst("name").Value));
                        }

                        return Task.FromResult(0);
                    }
                }
            });

            return app;

        }
    }
}