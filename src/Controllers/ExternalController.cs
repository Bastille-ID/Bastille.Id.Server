/*
 * Bastille.ID Identity Server
 * (c) Copyright Talegen, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
*/

namespace Bastille.Id.Server.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Text.Encodings.Web;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Extensions;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Core.Security;
    using Bastille.Id.Server.Common.Identity;
    using Bastille.Id.Server.Core.Common;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Controllers;
    using Bastille.Id.Server.Core.Security.Models;
    using Bastille.Id.Server.Models;
    using IdentityModel;
    using IdentityServer4;
    using IdentityServer4.Events;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Serilog;
    using Talegen.Common.Core.Extensions;
    using Talegen.Common.Messaging.Senders;
    using Vasont.AspnetCore.RedisClient;
    using Resources = Properties.Resources;
    using Bastille.Id.Models;
    using Talegen.AspNetCore.Web.Extensions;

    /// <summary>
    /// This class contains controller API endpoints related to external authentation.
    /// </summary>
    /// <seealso cref="IdentityControllerBase" />
    [AllowAnonymous]
    public class ExternalController : IdentityControllerBase
    {
        #region Private Fields

        /// <summary>
        /// Contains an instance of the resource store.
        /// </summary>
        private readonly IResourceStore resourceStore;

        /// <summary>
        /// The security service
        /// </summary>
        private readonly Lazy<SecurityService> securityService;

        /// <summary>
        /// The user service
        /// </summary>
        private readonly Lazy<UserService> userService;

        #endregion

        #region Public Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalController" /> class.
        /// </summary>
        /// <param name="appSettings">The application settings.</param>
        /// <param name="distributedCache">The distributed cache.</param>
        /// <param name="appContext">The application context.</param>
        /// <param name="userManager">The user manager.</param>
        /// <param name="signInManager">The sign in manager.</param>
        /// <param name="interaction">The interaction.</param>
        /// <param name="clientStore">The client store.</param>
        /// <param name="schemeProvider">The scheme provider.</param>
        /// <param name="events">The events.</param>
        /// <param name="messageSender">The message sender.</param>
        /// <param name="hostingEnvironment">The hosting environment.</param>
        /// <param name="resourceStore">The resource store.</param>
        /// <param name="logger">The logger.</param>
        public ExternalController(IOptions<ApplicationSettings> appSettings, IAdvancedDistributedCache distributedCache, ApplicationContext<ApplicationSettings> appContext,
            UserManager<User> userManager, SignInManager<User> signInManager, IIdentityServerInteractionService interaction, IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider, IEventService events, IMessageSender messageSender, IWebHostEnvironment hostingEnvironment,
            IResourceStore resourceStore, ILogger<ExternalController> logger)
            : base(appSettings, distributedCache, appContext, userManager, signInManager, interaction, clientStore, schemeProvider, events, messageSender, hostingEnvironment, logger)
        {
            this.resourceStore = resourceStore;

            // prep the security service
            this.securityService = new Lazy<SecurityService>(new SecurityService(new SecurityServiceContext
            {
                DataContext = appContext.DataContext,
                Cache = distributedCache,
                ErrorManager = appContext.ErrorManager,
                HttpContext = this.HttpContext,
                Principal = this.User,
                UserManager = this.UserManager
            }));

            // prep the user service
            this.userService = new Lazy<UserService>(new UserService(new UserServiceContext
            {
                Cache = distributedCache,
                ClientStore = clientStore,
                DataContext = appContext.DataContext,
                ErrorManager = appContext.ErrorManager,
                HttpContext = this.HttpContext,
                Principal = this.User,
                ResourceStore = resourceStore,
                SecurityService = this.Security,
                UserManager = this.UserManager,
                AuditLog = this.AuditLog
            }));
        }

        #endregion

        #region Private Properties

        /// <summary>
        /// Gets the user service.
        /// </summary>
        /// <value>The user service.</value>
        private UserService UserService => this.userService.Value;

        /// <summary>
        /// Gets the security.
        /// </summary>
        /// <value>The security.</value>
        private SecurityService Security => this.securityService.Value;

        #endregion

        /// <summary>
        /// Initiate roundtrip to external authentication provider
        /// </summary>
        /// <param name="scheme">The scheme.</param>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns>Returns the action result.</returns>
        /// <exception cref="Exception">invalid return URL</exception>
        [HttpGet]
        public IActionResult Challenge(string scheme, string returnUrl)
        {
            returnUrl = this.CheckReturnUrl(returnUrl);

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if (!this.Url.IsLocalUrl(returnUrl) && !this.Interaction.IsValidReturnUrl(returnUrl))
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception(Resources.InvalidReturnUrlText);
            }

            // start challenge and roundtrip the return URL and scheme
            AuthenticationProperties props = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Callback)),
                Items =
                {
                    { ControllerDefaults.ReturnUrlParameter, returnUrl },
                    { ControllerDefaults.SchemeParameter, scheme },
                }
            };

            return this.Challenge(props, scheme);
        }

        /// <summary>
        /// This operation will handle the callback from a successful external provider authentication event.
        /// </summary>
        /// <returns>Returns the action result.</returns>
        /// <exception cref="Exception">External authentication error</exception>
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            string redirectActionName = string.Empty;

            // read external identity from the temporary cookie
            var result = await this.HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            if (result?.Succeeded != true)
            {
                throw new Exception(Resources.ExternalLoginApplicationErrorText);
            }

            // retrieve return URL
            string returnUrl = result.Properties.Items.ContainsKey(ControllerDefaults.ReturnUrlParameter) ? result.Properties.Items[ControllerDefaults.ReturnUrlParameter] : ControllerDefaults.BaseRedirectUrl;

            if (this.Logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                this.Logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await this.FindUserFromExternalProviderAsync(result);

            // the user doesn't exist...
            if (user == null)
            {
                // determine if we can auto-provision
                if (this.Context.Settings.Account.AllowExternalRegistration)
                {
                    if (this.Context.Settings.Account.AllowExternalAutoProvision)
                    {
                        // auto-provision user account using the claims from external provider.
                        user = await this.ProvisionUserAsync(provider, providerUserId, claims, returnUrl: returnUrl);
                    }
                    else
                    {
                        redirectActionName = nameof(Register);
                    }
                }
                else
                {
                    this.Logger.LogWarning(Resources.ExternalProvisionDisabledErrorText);
                }
            }

            return await this.ProcessLoginAsync(result, user, provider, providerUserId, redirectActionName);
        }

        /// <summary>
        /// This operation will render the register user page for an external authentication.
        /// </summary>
        /// <param name="returnUrl">The return URL to redirect to after completion.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result.</returns>
        /// <exception cref="Exception">External authentication error</exception>
        [HttpGet]
        public async Task<IActionResult> Register(string returnUrl, CancellationToken cancellationToken)
        {
            // read external identity from the temporary cookie
            var result = await this.HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            returnUrl = this.CheckReturnUrl(returnUrl);
            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);
            this.ViewBag.RequiresName = this.Context.Settings.Account.RequireNameIdentification;

            if (result?.Succeeded != true)
            {
                throw new Exception(Resources.ExternalLoginApplicationErrorText);
            }

            if (this.Logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                this.Logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            IActionResult actionResult;

            if (result != null)
            {
                var vm = new ExternalLoginViewModel
                {
                    LoginProvider = result.Principal.Identity.AuthenticationType,
                    Email = result.Principal.GetEmail(),
                    FirstName = result.Principal.GetGivenName(),
                    LastName = result.Principal.GetFamilyName(),
                    ReturnUrl = returnUrl,
                    TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                    LoginLogoImageUrl = tenantConfig != null && !string.IsNullOrWhiteSpace(tenantConfig.LogoUrl) ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName
                };

                // render confirmation form.
                actionResult = this.View(vm);
            }
            else
            {
                // not authenticated
                actionResult = this.Redirect(returnUrl);
            }

            return actionResult;
        }

        /// <summary>
        /// This operation will receive the regster page model and create a new user using the external provider's claims and the email address/names specified
        /// in the model.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>Returns the action result.</returns>
        /// <exception cref="Exception"></exception>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(ExternalLoginViewModel model)
        {
            IActionResult actionResult = this.View(model);
            this.ViewBag.RequiresName = this.Context.Settings.Account.RequireNameIdentification;

            model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

            if (this.ModelState.IsValid)
            {
                AuthenticateResult loginInfo = await this.HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme).ConfigureAwait(false);

                if (loginInfo?.Succeeded != true)
                {
                    throw new Exception(loginInfo?.Failure?.RecurseMessages());
                }

                // lookup our user and external provider info
                var (user, provider, providerUserId, claims) = await this.FindUserFromExternalProviderAsync(loginInfo);

                // if no user found...
                if (user == null)
                {
                    // info has been confirmed, we're now registering a user from the external information provided.
                    user = new User
                    {
                        UserName = model.Email,
                        Email = model.Email
                    };

                    // this might be where you might initiate a custom workflow for user registration in this sample we don't show how that would be done, as
                    // our sample implementation simply auto-provisions new external user
                    user = await this.ProvisionUserAsync(provider, providerUserId, claims, user, model.ReturnUrl);
                }

                actionResult = await this.ProcessLoginAsync(loginInfo, user, provider, providerUserId);
            }
            else
            {
                this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
            }

            return actionResult;
        }

        /// <summary>
        /// Finds the user from external provider asynchronous.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <returns></returns>
        /// <exception cref="Exception">Unknown userid</exception>
        private async Task<(User user, string provider, string providerUserId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider) the most common claim type for that are the sub claim and the
            // NameIdentifier depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items[ControllerDefaults.SchemeParameter];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = await this.UserManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        /// <summary>
        /// Provisions the user asynchronous.
        /// </summary>
        /// <param name="provider">The provider.</param>
        /// <param name="providerUserId">The provider user identifier.</param>
        /// <param name="claims">The claims.</param>
        /// <param name="predefinedUser">The predefined user.</param>
        /// <param name="returnUrl">Contains the return URL.</param>
        /// <returns>Returns the user entity provisioned.</returns>
        /// <exception cref="Exception">An exception is thrown if the user provision was unsuccessful.</exception>
        private async Task<User> ProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims, User predefinedUser = null, string returnUrl = null)
        {
            // create a list of claims that we want to transfer into our store
            List<Claim> filtered = new List<Claim>();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;

            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;

                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var user = predefinedUser ?? new User
            {
                Email = email,
                UserName = email
            };

            var identityResult = await this.UserManager.CreateAsync(user);

            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }

            if (filtered.Any())
            {
                identityResult = await this.UserManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded)
                {
                    throw new Exception(identityResult.Errors.First().Description);
                }
            }

            identityResult = await this.UserManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));

            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }

            // generate a code
            var code = await this.UserManager.GenerateEmailConfirmationTokenAsync(user);

            if (this.Context.Settings.Account.RequiresEmailVerification)
            {
                // generate a callback URL
                string callbackUrl = this.Url.Action(action: nameof(AccountController.ConfirmEmail), controller: ControllerDefaults.AccountControllerName, values: new { userId = user.Id, code, returnUrl = returnUrl }, protocol: this.Request.Scheme);

                // submit the register URL to the user via message sender
                await this.SendAccountEmailAsync(callbackUrl, user, Resources.VerifyEmailSubjectText, SecurityDefaults.VerifyAccountTemplateName);
            }
            else
            {
                // no verification required. Simply validate automatically.
                await this.UserManager.ConfirmEmailAsync(user, code);
            }

            return user;
        }

        /// <summary>
        /// Processes the login asynchronous.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <param name="user">The user.</param>
        /// <param name="provider">The provider.</param>
        /// <param name="providerUserId">The provider user identifier.</param>
        /// <param name="redirectActionName">Name of the redirect action.</param>
        /// <returns></returns>
        private async Task<IActionResult> ProcessLoginAsync(AuthenticateResult result, User user, string provider, string providerUserId, string redirectActionName = "")
        {
            // this allows us to collect any additional claims or properties for the specific protocols used and store them in the local auth cookie. this is
            // typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            RedirectModel redirectModel = new RedirectModel
            {
                ReturnUrl = this.BuildAbsoluteUrl(ControllerDefaults.BaseRedirectUrl)
            };

            ProcessLoginCallback(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user we must issue the cookie maually, and can't use the SignInManager because it doesn't expose an API to issue
            // additional claims from the login workflow
            var principal = await this.SignInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);
            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id.ToString();

            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await HttpContext.SignInAsync(isuser, localSignInProps);

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items[ControllerDefaults.ReturnUrlParameter] ?? ControllerDefaults.BaseRedirectUrl;

            // check if external login is in the context of an OIDC request
            var context = await this.Interaction.GetAuthorizationContextAsync(returnUrl);
            await this.Events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id.ToString(), name, true, context?.Client.ClientId));

            IActionResult actionResult = this.Redirect(returnUrl);

            // we want to provision but we'll need manual intervention and email validation. redirect to the External Register page
            if (!string.IsNullOrWhiteSpace(redirectActionName))
            {
                actionResult = this.RedirectToAction(redirectActionName, redirectModel);
            }

            return actionResult;
        }

        // if the external login is OIDC-based, there are certain things we need to preserve to make logout work this will be different for WS-Fed, SAML2p or
        // other protocols
        private static void ProcessLoginCallback(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);

            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var idToken = externalResult.Properties.GetTokenValue("id_token");

            if (idToken != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
            }
        }
    }
}