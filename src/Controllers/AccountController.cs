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
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Core.Security;
    using Bastille.Id.Models;
    using Bastille.Id.Models.Logging;
    using Bastille.Id.Models.Security;
    using Bastille.Id.Server.Common.Identity;
    using Bastille.Id.Server.Core.Common;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Controllers;
    using Bastille.Id.Server.Core.Security.Models;
    using IdentityModel;
    using IdentityServer4.Events;
    using IdentityServer4.Extensions;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Serilog;
    using Talegen.Common.Core.Errors;
    using Talegen.Common.Core.Errors.Models;
    using Talegen.Common.Messaging.Senders;
    using Vasont.AspnetCore.RedisClient;
    using ErrorMessage = Talegen.Common.Core.Errors.ErrorMessage;
    using Resources = Properties.Resources;

    /// <summary>
    /// This is the main interface of the identity server containing the landing page for login/logout
    /// </summary>
    /// <seealso cref="IdentityControllerBase" />
    public class AccountController : IdentityControllerBase
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
        /// Initializes a new instance of the <see cref="AccountController" /> class.
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
        public AccountController(IOptions<ApplicationSettings> appSettings, IAdvancedDistributedCache distributedCache, ApplicationContext<ApplicationSettings> appContext,
            UserManager<User> userManager, SignInManager<User> signInManager, IIdentityServerInteractionService interaction, IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider, IEventService events, IMessageSender messageSender, IWebHostEnvironment hostingEnvironment,
            IResourceStore resourceStore, ILogger<AccountController> logger)
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

        /// <summary>
        /// Gets the working pictures cache path.
        /// </summary>
        /// <value>The working pictures cache path.</value>
        private string WorkingPicturesCachePath
        {
            get
            {
                string path = Path.Combine(this.ApplicationSettings.Storage.RootPath, "Pictures");

                // if the temp picture cache folder doesn't exist...
                if (!Directory.Exists(path))
                {
                    try
                    {
                        // create it.
                        Directory.CreateDirectory(path);
                    }
                    catch (IOException ex)
                    {
                        this.Logger.LogError(ex, Properties.Resources.ErrorCreateDirectoryText, path, ex.Message);
                    }
                }

                return path;
            }
        }

        #endregion

        #region Account Profile Controller Methods

        /// <summary>
        /// Returns the main dashboard landing page of the the application once the user has authenticated.
        /// </summary>
        /// <returns>Returns the action result view.</returns>
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            ManageUserProfileModel model = await this.BuildManageUserProfileModelAsync(cancellationToken);
            return this.View(model);
        }

        /// <summary>
        /// Errors the specified model.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Error(ErrorViewModel<IErrorMessage> model)
        {
            if (model.Error == null)
            {
                if (this.Context.ErrorManager.HasErrors)
                {
                    model.Error = this.Context.ErrorManager.Messages.FirstOrDefault();
                }
                else
                {
                    model.Error = this.Context.ErrorManager.CreateErrorMessage(this.StatusMessage, ErrorType.Critical);
                }
            }

            return this.View(model);
        }

        #endregion

        #region Login/Logout Controller Methods

        /// <summary>
        /// This controller method is used to display the login page.
        /// </summary>
        /// <param name="returnUrl">Contains the redirect URL to return to after login.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl, CancellationToken cancellationToken)
        {
            IActionResult resultView;

            // if the user is authenticated and valid URL...
            if (this.User != null && this.User.Identity.IsAuthenticated && (this.Interaction.IsValidReturnUrl(returnUrl) || this.Url.IsLocalUrl(returnUrl)))
            {
                // we are already logged in, redirect to return URL specified.
                Log.Information(Resources.LoginRedirectWarningText, this.CurrentUserId, returnUrl);
                resultView = this.Redirect(returnUrl);
            }
            else
            {
                // build a model so we know what to show on the login page
                var vm = await this.BuildLoginViewModelAsync(returnUrl, cancellationToken).ConfigureAwait(false);

                // reset step.
                vm.Step = LoginStep.UserName;
                vm.IsUserNameVerified = false;

                // if this is an external login only, redirect...
                if (vm.IsExternalLoginOnly)
                {
                    // we only have one option for logging in and it's an external provider, redirect to our external challenge
                    resultView = this.RedirectToAction(nameof(ExternalController.Challenge), ControllerDefaults.ExternalControllerName, new { Scheme = vm.ExternalLoginScheme, ReturnUrl = returnUrl });
                }
                else
                {
                    // otherwise, let's show the login dialog prompt.
                    resultView = this.View(vm);
                }
            }

            return resultView;
        }

        /// <summary>
        /// This controller method is used to handle post from username/password login.
        /// </summary>
        /// <param name="model">Contains a <see cref="LoginInputModel" /> containing login credential information.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, CancellationToken cancellationToken)
        {
            LoginViewModel viewModel = await this.BuildLoginViewModelAsync(model, cancellationToken).ConfigureAwait(false);
            IActionResult actionResult = this.View(viewModel);

            // set user name has been retrieved and verified.
            viewModel.IsUserNameVerified = model.Step == LoginStep.UserName;
            AuthorizationRequest authRequest = await this.Interaction.GetAuthorizationContextAsync(model.ReturnUrl).ConfigureAwait(false);

            // if step is user name or password input
            if (model.Step != LoginStep.Cancel)
            {
                // if our interface is multi-step (retrieve user name, then ask for password) then we need to remove Password validation check.
                if (!viewModel.IsUserNameVerified)
                {
                    // override the model state for this call to not do the required check for the Password field
                    this.ModelState.Remove(nameof(model.Password));
                }

                // is the model state valid?
                if (this.ModelState.IsValid)
                {
                    User userFound = null;

                    switch (this.Context.Settings.Account.RequiredLoginIdentifier)
                    {
                        case LoginIdentifierMethod.Email:
                            userFound = await this.UserManager.FindByEmailAsync(model.UserName);
                            break;

                        case LoginIdentifierMethod.UserName:
                            userFound = await this.UserManager.FindByNameAsync(model.UserName);
                            break;

                        case LoginIdentifierMethod.UserNameOrEmail:
                            userFound = await this.UserManager.FindByEmailAsync(model.UserName);

                            if (userFound == null)
                            {
                                userFound = await this.UserManager.FindByNameAsync(model.UserName);
                            }

                            break;

                        case LoginIdentifierMethod.UserNameOrEmailOrPhone:
                            userFound = await this.Context.DataContext.Users.FirstOrDefaultAsync(u => u.Email == model.UserName || u.PhoneNumber == model.UserName);

                            if (userFound == null)
                            {
                                userFound = await this.UserManager.FindByNameAsync(model.UserName);
                            }

                            break;
                    }

                    // user was found using required login identifier...
                    if (userFound != null)
                    {
                        // if we've not verified the user yet...
                        if (!viewModel.IsUserNameVerified)
                        {
                            // now the user name is verified... let's request a password...
                            viewModel.IsUserNameVerified = true;
                        }
                        else
                        {
                            // the user name was validated already, so we're moving on to password validation and signin
                            Microsoft.AspNetCore.Identity.SignInResult result = await this.SignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberLogin, lockoutOnFailure: true).ConfigureAwait(false);

                            // if the user information checks out
                            if (result.Succeeded)
                            {
                                // login was successful, so set the last login date.
                                userFound.LastLoginDate = DateTime.UtcNow;

                                // if the user had a lockout...
                                if (userFound.LockoutEnd.HasValue)
                                {
                                    // reset and save the user record.
                                    userFound.LockoutEnd = null;
                                    await this.Context.DataContext.SaveChangesAsync(cancellationToken);
                                }

                                // audit and raise login success event
                                await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Success, this.ClientAddress, string.Empty, userFound.Id, cancellationToken: cancellationToken).ConfigureAwait(false);
                                await this.Events.RaiseAsync(new UserLoginSuccessEvent(userFound.UserName, userFound.Id.ToString(), userFound.UserName)).ConfigureAwait(false);

                                // is the account locked out?
                                if (result.IsLockedOut)
                                {
                                    // raise the login failed
                                    await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Fail, this.ClientAddress, Resources.UserAccountLockedMessageText, userFound.Id, cancellationToken: cancellationToken);
                                    actionResult = this.RedirectToAction(nameof(AccountController.Lockout), ControllerDefaults.AccountControllerName);
                                }
                                else if (result.RequiresTwoFactor)
                                {
                                    // determine if we need to do two-factor for this user... we will redirect to our two-factor page for this account...
                                    actionResult = this.RedirectToAction(nameof(AccountController.TwoFactorLogin), ControllerDefaults.AccountControllerName, new { model.ReturnUrl, rememberLogin = model.RememberLogin });
                                }
                                else if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && (this.Interaction.IsValidReturnUrl(model.ReturnUrl) || this.Url.IsLocalUrl(model.ReturnUrl)))
                                {
                                    // otherwise check to ensure the return address is valid, if so, redirect to it.
                                    actionResult = this.Redirect(model.ReturnUrl);
                                }
                                else
                                {
                                    // if the return address was invalid, redirect back to the root of the app.
                                    actionResult = this.Redirect(ControllerDefaults.BaseRedirectUrl);
                                }
                            }
                            else
                            {
                                string message = Resources.PasswordOrUserNameIncorrectText;

                                if (result.IsLockedOut)
                                {
                                    message = Resources.UserAccountLockedMessageText;
                                }

                                await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Fail, this.ClientAddress, message, userFound.Id).ConfigureAwait(false);
                                await this.Events.RaiseAsync(new UserLoginFailureEvent(model.UserName, message)).ConfigureAwait(false);
                                this.ModelState.AddModelError(string.Empty, message);
                            }
                        }
                    }
                    else
                    {
                        await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Fail, this.ClientAddress, string.Format(Resources.UserNameNotFoundErrorText, model.UserName)).ConfigureAwait(false);
                        this.ModelState.AddModelError(string.Empty, Resources.UserNameIncorrectText);

                        //await this.ReportLoginFailureAsync(model, userFound.Id, result);
                    }
                }
            }
            else if (authRequest != null)
            {
                // the user clicked the "cancel" button
                await this.Interaction.DenyAuthorizationAsync(authRequest, AuthorizationError.AccessDenied);

                // if the user cancels, send a result back into IdentityServer as if they denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await this.Interaction.GrantConsentAsync(authRequest, new ConsentResponse { Error = AuthorizationError.AccessDenied }).ConfigureAwait(false);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                actionResult = this.Redirect(model.ReturnUrl);
            }
            else
            {
                // since we don't have a valid context, we're at a loss. Head to the base directory.
                actionResult = this.RedirectToAction(nameof(this.Index));
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method is called to render the two-factor authentication page.
        /// </summary>
        /// <param name="returnUrl">Contains the redirect URL to return to after login.</param>
        /// <param name="rememberLogin">Contains a value indicating whether to remember the login.</param>
        /// <returns>Returns the controller result.</returns>
        [HttpGet]
        public async Task<IActionResult> TwoFactorLogin(string returnUrl, bool rememberLogin)
        {
            IActionResult result = this.NotFound(Resources.TwoFactorUserNotFoundText);

            // Ensure the user has gone through the username & password screen first
            var user = await this.SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user != null)
            {
                result = this.View(new LoginTwoFactorViewModel { ReturnUrl = returnUrl, RememberLogin = rememberLogin });
            }

            return result;
        }

        /// <summary>
        /// This controller method is used to process the two-factor authentication login.
        /// </summary>
        /// <param name="model">Contains the model to process.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> TwoFactorLogin(LoginTwoFactorViewModel model, CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.View(model);

            if (this.ModelState.IsValid)
            {
                // if no return url specified, return to home
                model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

                // get user two factor authentication
                User user = await this.SignInManager.GetTwoFactorAuthenticationUserAsync();

                // if the two factor account was found...
                if (user != null)
                {
                    // clean-up code
                    string authenticatorCode = model.Code.Replace(" ", string.Empty, StringComparison.InvariantCulture).Replace("-", string.Empty, StringComparison.InvariantCulture);

                    // check code
                    var result = await this.SignInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, model.RememberLogin, model.RememberDevice);

                    // if the authentication was successful...
                    if (result.Succeeded)
                    {
                        Log.Information(Resources.TwoFactorAuthenticationSuccessLogText, ErrorCategory.General, user.UserName, user.Id);
                        actionResult = this.Redirect(model.ReturnUrl);
                    }
                    else if (result.IsLockedOut)
                    {
                        Log.Warning(Resources.LoginAccountLockedMessageText, user.UserName, user.Id);
                        actionResult = this.RedirectToAction(nameof(this.Lockout));
                    }
                    else
                    {
                        this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
                    }
                }
                else
                {
                    Log.Warning(Resources.TwoFactorUserNotFoundText);
                    actionResult = this.NotFound(Resources.TwoFactorUserNotFoundText);
                }
            }
            else
            {
                this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
            }

            return actionResult;
        }

        /// <summary>
        /// Logins the with recovery code.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns></returns>
        /// <exception cref="ApplicationException">Unable to load two-factor authentication user.</exception>
        [HttpGet]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            IActionResult result = this.NotFound(Resources.TwoFactorUserNotFoundText);

            // Ensure the user has gone through the username & password screen first
            User user = await this.SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user != null)
            {
                this.ViewData[ControllerDefaults.ReturnUrlParameter] = returnUrl;
                result = this.View();
            }

            return result;
        }

        /// <summary>
        /// Logins the with recovery code.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <param name="returnUrl">The return URL.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the controller result.</returns>
        /// <exception cref="ApplicationException">Unable to load two-factor authentication user.</exception>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null, CancellationToken cancellationToken = default)
        {
            IActionResult actionResult = this.View(model);

            if (this.ModelState.IsValid)
            {
                var user = await this.SignInManager.GetTwoFactorAuthenticationUserAsync();

                if (user != null)
                {
                    // if no return url specified, return to home
                    model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

                    string recoveryCode = model.RecoveryCode.Replace(" ", string.Empty, StringComparison.InvariantCulture);
                    var result = await this.SignInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
                    string message = string.Empty;

                    if (result.Succeeded)
                    {
                        message = string.Format(Resources.RecoveryCodeSuccessLogText, user.Id);
                        await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Success, this.ClientAddress, message, user.Id, cancellationToken: cancellationToken);
                        Log.Information(message);
                        actionResult = this.Redirect(returnUrl);
                    }
                    else if (result.IsLockedOut)
                    {
                        message = string.Format(Resources.LoginAccountLockedMessageText, user.Id);
                        await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Fail, this.ClientAddress, message, user.Id, cancellationToken: cancellationToken);
                        Log.Warning(message);
                        actionResult = this.RedirectToAction(nameof(AccountController.Lockout));
                    }
                    else
                    {
                        message = string.Format(Resources.InvalidRecoveryCodeText, user.UserName);
                        Log.Warning(message);
                        await this.AuditLog.LogAsync(AuditEvent.Login, AuditResult.Fail, this.ClientAddress, message, user.Id, cancellationToken: cancellationToken);
                        this.ModelState.AddModelError(string.Empty, Resources.InvalidRecoveryCodeText);
                    }
                }
                else
                {
                    actionResult = this.NotFound(Resources.TwoFactorUserNotFoundText);
                }
            }
            else
            {
                this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
            }

            return actionResult;
        }

        /// <summary>
        /// Lockouts this instance.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Lockout()
        {
            return this.View();
        }

        /// <summary>
        /// This controller method is used to display the logout page.
        /// </summary>
        /// <param name="logoutId">Contains a logout identity</param>
        /// <param name="returnUrl">Contains the optional return url</param>
        /// <param name="cancellationToken">Contains a cancellation token</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId, string returnUrl = "", CancellationToken cancellationToken = default)
        {
            IActionResult actionResult;

            LogoutInputModel model = new LogoutInputModel
            {
                LogoutId = logoutId,
                ReturnUrl = returnUrl
            };

            // if we're showing a logout prompt...
            if (this.ApplicationSettings.Account.ShowLogoutPrompt)
            {
                // build a model so the logout page knows what to display
                LogoutViewModel vm = await this.BuildLogoutViewModelAsync(model, cancellationToken).ConfigureAwait(false);
                actionResult = this.View(vm);
            }
            else
            {
                actionResult = await this.Logout(model, cancellationToken);
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method is used to handle logout page post.
        /// </summary>
        /// <param name="model">Contains the <see cref="LogoutInputModel" /> model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model, CancellationToken cancellationToken)
        {
            // build a model so the logged out page knows what to display
            LoggedOutViewModel viewModel = await this.BuildLoggedOutViewModelAsync(model, cancellationToken).ConfigureAwait(false);
            IActionResult actionResult = this.View(ControllerDefaults.LoggedOutViewName, viewModel);

            if (this.User?.Identity.IsAuthenticated == true)
            {
                Guid userId = this.CurrentUserId;
                string userName = this.CurrentUserName;

                // delete local authentication cookie
                await this.SignInManager.SignOutAsync();

                // log logout event
                await this.AuditLog.LogAsync(AuditEvent.Logout, AuditResult.Success, this.ClientAddress, string.Empty, userId).ConfigureAwait(false);

                // raise the logout event
                await this.Events.RaiseAsync(new UserLogoutSuccessEvent(this.CurrentUserId.ToString(), userName)).ConfigureAwait(false);
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (viewModel.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back to us after the user has logged out. this allows us to then complete our
                // single sign-out processing.
                string url = this.Url.Action(nameof(this.Logout), new { logoutId = viewModel.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                actionResult = this.SignOut(new AuthenticationProperties { RedirectUri = url }, viewModel.ExternalAuthenticationScheme);
            }

            return actionResult;
        }

        #endregion

        #region Registration Controller Methods

        /// <summary>
        /// This controller method is used to display the registration page.
        /// </summary>
        /// <param name="returnUrl">Contains a return URL that was passed to the login page.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> Register(string returnUrl = "", CancellationToken cancellationToken = default)
        {
            IActionResult actionResult;

            if (this.ApplicationSettings.Account.AllowRegistration)
            {
                this.ViewBag.RequiresName = this.ApplicationSettings.Account.RequireNameIdentification;
                this.ViewBag.TermsUrl = this.ApplicationSettings.Account.TermsUrl != null ? this.ApplicationSettings.Account.TermsUrl.ToString() : ControllerDefaults.DefaultTermsUrl;

                string placeholderText = string.Empty;
                TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);

                switch (this.Context.Settings.Account.RequiredLoginIdentifier)
                {
                    case LoginIdentifierMethod.Email:
                        placeholderText = Resources.EmailText;
                        break;

                    case LoginIdentifierMethod.UserName:
                        placeholderText = Resources.UserNameText;
                        break;

                    case LoginIdentifierMethod.UserNameOrEmail:
                        placeholderText = Resources.IdentifierPlaceholderEmailOrUserNameText;
                        break;

                    case LoginIdentifierMethod.UserNameOrEmailOrPhone:
                        placeholderText = Resources.IdentifierPlaceholderEmailOrUserNameOrPhoneText;
                        break;
                }

                RegisterViewModel model = new RegisterViewModel
                {
                    UserNamePlaceholder = placeholderText,
                    EnableLocalLogin = this.Context.Settings.Account.AllowLocalLogin,
                    ReturnUrl = returnUrl,
                    TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                    LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName,
                    ExternalProviders = await this.FindExternalProvidersAsync(returnUrl)
                };

                actionResult = this.View(model);
            }
            else
            {
                actionResult = this.NotFound();
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method is used to receive and process a new account creation request.
        /// </summary>
        /// <param name="model">Contains the account creation model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.View(model);

            if (this.ApplicationSettings.Account.AllowRegistration)
            {
                this.ViewBag.RequiresName = this.ApplicationSettings.Account.RequireNameIdentification;
                this.ViewBag.TermsUrl = this.ApplicationSettings.Account.TermsUrl != null ? this.ApplicationSettings.Account.TermsUrl.ToString() : ControllerDefaults.DefaultTermsUrl;

                string placeholderText = string.Empty;
                TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, model.ReturnUrl, cancellationToken);

                model.UserNamePlaceholder = placeholderText;
                model.EnableLocalLogin = this.Context.Settings.Account.AllowLocalLogin;
                model.TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty;
                model.LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName;
                model.ExternalProviders = await this.FindExternalProvidersAsync(model.ReturnUrl);

                if (this.ModelState.IsValid)
                {
                    if (!this.Context.Settings.Account.RequireNameIdentification ||
                       (!string.IsNullOrWhiteSpace(model.FirstName) && !string.IsNullOrWhiteSpace(model.LastName)))
                    {
                        model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

                        User user = new User
                        {
                            Email = model.Email,
                            UserName = !string.IsNullOrWhiteSpace(model.UserName) ? model.UserName : model.Email
                        };

                        // if a mobile number is set...
                        if (!string.IsNullOrWhiteSpace(model.PhoneNumber))
                        {
                            // add to user profile.
                            user.PhoneNumber = model.PhoneNumber;
                        }

                        // create the user...
                        var result = await this.UserManager.CreateAsync(user, model.Password);

                        // upon success...
                        if (result.Succeeded)
                        {
                            // add default picture, locale, and zone info claims
                            List<Claim> claims = new List<Claim>
                            {
                                //new Claim(JwtClaimTypes.Picture, this.BuildAbsoluteUrl("~/Account/Picture/" + user.Id)),
                                new Claim(JwtClaimTypes.Locale, this.Context.DataContext.Languages.Where(l => l.Default).Select(l => l.LanguageCode).FirstOrDefault()),
                                new Claim(JwtClaimTypes.ZoneInfo, this.Context.DataContext.TimeZones.Where(l => l.Default).Select(l => l.TimeZoneId).FirstOrDefault())
                            };

                            // if we required name info, add it here.
                            if (this.Context.Settings.Account.RequireNameIdentification || !string.IsNullOrWhiteSpace(model.FirstName) || !string.IsNullOrWhiteSpace(model.LastName))
                            {
                                // add claims
                                claims.Add(new Claim(JwtClaimTypes.GivenName, model.FirstName));
                                claims.Add(new Claim(JwtClaimTypes.FamilyName, model.LastName));
                            }

                            // store claims
                            await this.UserManager.AddClaimsAsync(user, claims);

                            var code = await this.UserManager.GenerateEmailConfirmationTokenAsync(user);

                            if (this.Context.Settings.Account.RequiresEmailVerification)
                            {
                                // generate a callback URL
                                string callbackUrl = this.Url.Action(action: nameof(AccountController.ConfirmEmail), controller: ControllerDefaults.AccountControllerName, values: new { userId = user.Id, code, returnUrl = model.ReturnUrl }, protocol: this.Request.Scheme);

                                // submit the register URL to the user via message sender
                                await this.SendAccountEmailAsync(callbackUrl, user, Resources.VerifyEmailSubjectText, SecurityDefaults.VerifyAccountTemplateName, cancellationToken: cancellationToken);
                            }
                            else
                            {
                                // no verification required. Simply validate automatically.
                                await this.UserManager.ConfirmEmailAsync(user, code);
                            }

                            // if we allow the unverified user to sign-in...
                            if (this.Context.Settings.Account.AllowSignInBeforeEmailVerification)
                            {
                                // authenticate.
                                await this.SignInManager.SignInAsync(user, isPersistent: false);
                            }

                            // redirect to the return URL...
                            actionResult = this.LocalRedirect(model.ReturnUrl);
                        }
                        else
                        {
                            this.AddErrors(result);
                        }
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(model.FirstName))
                        {
                            this.ModelState.AddModelError(nameof(model.FirstName), Resources.FirstNameRequiredText);
                        }

                        if (string.IsNullOrWhiteSpace(model.LastName))
                        {
                            this.ModelState.AddModelError(nameof(model.LastName), Resources.LastNameRequiredText);
                        }
                    }
                }
                else
                {
                    this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
                }
            }
            else
            {
                actionResult = this.NotFound();
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method is used to display the confirm e-mail page.
        /// </summary>
        /// <param name="model">Contains the confirmation return view model.</param>
        /// <param name="cancellationToken">Contains the cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmationReturnViewModel model, CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.Redirect(ControllerDefaults.BaseRedirectUrl);

            if (this.ApplicationSettings.Account.AllowRegistration)
            {
                if (!string.IsNullOrWhiteSpace(model.UserId) && !string.IsNullOrWhiteSpace(model.Code))
                {
                    User user = await this.UserManager.FindByIdAsync(model.UserId);

                    if (user != null)
                    {
                        // validate email confirmation
                        IdentityResult result = await this.UserManager.ConfirmEmailAsync(user, model.Code);

                        model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

                        if (result.Succeeded && (this.Url.IsLocalUrl(model.ReturnUrl) || this.Interaction.IsValidReturnUrl(model.ReturnUrl)))
                        {
                            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, model.ReturnUrl, cancellationToken);
                            model.TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty;
                            model.LoginLogoImageUrl = tenantConfig != null && !string.IsNullOrWhiteSpace(tenantConfig.LogoUrl) ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName;
                            this.StatusMessage = Resources.EmailConfirmedPromptText;
                            this.StatusMessageType = StatusMessageResultType.Success;
                            actionResult = this.View(model);
                        }
                        else
                        {
                            this.StatusMessage = Resources.EmailConfirmErrorText;
                            this.StatusMessageType = StatusMessageResultType.Warning;
                            this.Context.ErrorManager.Critical(Resources.EmailConfirmErrorText, ErrorCategory.Application);
                            actionResult = this.RedirectToAction(nameof(this.Error));
                        }
                    }
                    else
                    {
                        actionResult = this.NotFound(string.Format(CultureInfo.CurrentCulture, Id.Core.Properties.Resources.ErrorUserIdentityNotFoundText, model.UserId));
                    }
                }
                else
                {
                    this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
                    this.Context.ErrorManager.Warning(Resources.EmailConfirmErrorText, ErrorCategory.Security);
                }

                return actionResult;
            }
            else
            {
                actionResult = this.NotFound();
            }

            return actionResult;
        }

        #endregion

        #region Password Reset Controller Methods

        /// <summary>
        /// This controller method is used to display the forgotten password page.
        /// </summary>
        /// <param name="returnUrl">Contains the return url of the login page.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> ForgotPassword(string returnUrl = "", CancellationToken cancellationToken = default)
        {
            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);

            ForgotPasswordViewModel model = new ForgotPasswordViewModel
            {
                EnableLocalLogin = this.ApplicationSettings.Account.AllowLocalLogin,
                AllowRegistration = this.ApplicationSettings.Account.AllowRegistration,
                ReturnUrl = returnUrl,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName,
            };

            return this.View(model);
        }

        /// <summary>
        /// This controller method is used to handle the post from the forgotten password page.
        /// </summary>
        /// <param name="model">Contains a <see cref="ForgotPasswordViewModel" /> model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page result.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, CancellationToken cancellationToken)
        {
            // Don't reveal that the user does not exist or is not confirmed
            IActionResult actionResult = this.RedirectToAction(nameof(AccountController.ForgotPasswordConfirmation), new { returnUrl = model?.ReturnUrl });

            if (model != null && this.ModelState.IsValid)
            {
                User user = await this.UserManager.FindByEmailAsync(model.Email).ConfigureAwait(false);

                // if the user was found...
                if (user != null && (!this.Context.Settings.Account.RequiresEmailVerification || await this.UserManager.IsEmailConfirmedAsync(user).ConfigureAwait(false)))
                {
                    string code = await this.UserManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
                    string callbackUrl = this.Url.Action(action: nameof(AccountController.ResetPassword), controller: ControllerDefaults.AccountControllerName, values: new { user.Id, code, model.ReturnUrl }, protocol: this.Request.Scheme);

                    await this.AuditLog.LogAsync(AuditEvent.Password, AuditResult.Success, this.ClientAddress, string.Format(Resources.PasswordResetLogMessageText, user.Id), cancellationToken: cancellationToken).ConfigureAwait(false);

                    // submit the register URL to the user via message sender
                    await this.SendAccountEmailAsync(callbackUrl, user, Resources.ResetPasswordEmailSubjectText, SecurityDefaults.ResetPasswordTemplateName, cancellationToken: cancellationToken);
                }
            }

            // If we got this far, something failed, redisplay form
            return actionResult;
        }

        /// <summary>
        /// This controller method is used to display the forgotten password confirmation page.
        /// </summary>
        /// <param name="returnUrl">Contains the return url of the login page.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> ForgotPasswordConfirmation(string returnUrl = "", CancellationToken cancellationToken = default)
        {
            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);

            ConfirmationReturnViewModel model = new ConfirmationReturnViewModel
            {
                ReturnUrl = returnUrl,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName
            };

            return this.View(model);
        }

        /// <summary>
        /// This controller method is used to display the reset password page interface.
        /// </summary>
        /// <param name="id">Contains the unique identifier of the user who is resetting their password.</param>
        /// <param name="returnUrl">Contains the return url of the login page.</param>
        /// <param name="code">Contains the unique code for the password reset page.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> ResetPassword(string id, string returnUrl = "", string code = null, CancellationToken cancellationToken = default)
        {
            IActionResult result;

            if (code == null)
            {
                throw new ApplicationException(Resources.CodeRequiredErrorText);
            }

            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);
            User user = await this.UserManager.FindByIdAsync(id);

            if (user != null)
            {
                // verify the token code
                if (await this.UserManager.VerifyUserTokenAsync(user, this.UserManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", code))
                {
                    ResetPasswordViewModel model = new ResetPasswordViewModel
                    {
                        Code = code,
                        Email = user.Email,
                        ReturnUrl = returnUrl,
                        TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                        LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName,
                        EnableLocalLogin = this.ApplicationSettings.Account.AllowLocalLogin
                    };

                    result = this.View(model);
                }
                else
                {
                    string message = "Invalid security code for password reset and/or the reset token has expired.";
                    this.StatusMessage = message;
                    this.StatusMessageType = StatusMessageResultType.Danger;
                    this.Context.ErrorManager.CriticalForbidden(message, ErrorCategory.Security);
                    result = this.RedirectToAction(nameof(this.Error));
                }
            }
            else
            {
                string message = Bastille.Id.Core.Properties.Resources.ErrorUserNotFoundText;
                this.StatusMessage = message;
                this.StatusMessageType = StatusMessageResultType.Danger;
                this.Context.ErrorManager.CriticalNotFound(message, ErrorCategory.Application);
                result = this.RedirectToAction(nameof(this.Error));
            }

            return result;
        }

        /// <summary>
        /// This controller method is used to handle the reset password post form data.
        /// </summary>
        /// <param name="model">Contains a <see cref="ResetPasswordViewModel" /> object containing the new password information.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.View(model);

            if (this.ModelState.IsValid)
            {
                User user = await this.UserManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                AuditResult auditResult = AuditResult.Success;
                string auditMessage;

                if (user != null)
                {
                    IdentityResult result = await this.UserManager.ResetPasswordAsync(user, model.Code, model.Password).ConfigureAwait(false);

                    if (result.Succeeded)
                    {
                        auditMessage = string.Format(Resources.PasswordResetSuccessLogMessageText, user.Id);
                        actionResult = this.RedirectToAction(nameof(this.ResetPasswordConfirmation), new { returnUrl = model.ReturnUrl });
                    }
                    else
                    {
                        auditResult = AuditResult.Fail;
                        auditMessage = string.Format(Resources.PasswordResetFailLogMessageText, user.Id);
                        this.AddErrors(result);
                    }
                }
                else
                {
                    auditResult = AuditResult.Fail;
                    auditMessage = string.Format(Resources.PasswordResetFailInvalidUserMessageText, model.Email);

                    // Don't reveal that the user does not exist
                    actionResult = this.RedirectToAction(nameof(this.ResetPasswordConfirmation));
                }

                await this.AuditLog.LogAsync(AuditEvent.Password, auditResult, this.ClientAddress, auditMessage, this.OptionalCurrentUserId, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            else
            {
                this.AddModelErrorsToStatus(StatusMessageResultType.Danger);
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method is used to display the reset password confirmation page.
        /// </summary>
        /// <param name="returnUrl">Contains the return url of the login page.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the action result for the page view.</returns>
        [HttpGet]
        public async Task<IActionResult> ResetPasswordConfirmation(string returnUrl = "", CancellationToken cancellationToken = default)
        {
            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);
            ConfirmationReturnViewModel model = new ConfirmationReturnViewModel
            {
                ReturnUrl = returnUrl,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName
            };

            return this.View(model);
        }

        #endregion

        #region Private Profile Methods

        /// <summary>
        /// Builds the manage user profile model asynchronous.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Returns a new <see cref="ManageUserProfileModel" /> object.</returns>
        private async Task<ManageUserProfileModel> BuildManageUserProfileModelAsync(CancellationToken cancellationToken)
        {
            ManageUserProfileModel model = new ManageUserProfileModel
            {
                StatusMessage = this.StatusMessage,
                StatusType = this.StatusMessageType
            };

            var user = await this.UserManager.GetUserAsync(this.User);

            // if the current user was found...
            if (user != null)
            {
                // populate the model with user record values...
                model.Email = user.Email;
                model.IsEmailConfirmed = user.EmailConfirmed;
                model.PictureUrl = this.Url.Action("Picture", new { id = user.Id });
                model.PhoneNumber = user.PhoneNumber;

                // load user claims
                this.PopulateClaims(model, await this.UserManager.GetClaimsAsync(user));

                // get the first organization the user is a member of
                var group = await this.Context.DataContext.Groups
                    .AsNoTracking()
                    .FirstOrDefaultAsync(o => o.Members.Any(ou => ou.UserId == this.CurrentUserId), cancellationToken);

                if (group != null)
                {
                    // set the user's organization name
                    model.TenantName = group.Name;
                }

                // setup lists data
                model.LanguageList = new SelectList(this.Context.DataContext.Languages.Where(l => l.Active).OrderBy(l => l.Name), nameof(Language.LanguageCode), nameof(Language.Name), model.Locale);
                model.TimeZoneList = new SelectList(this.Context.DataContext.TimeZones.Where(t => t.Active).OrderBy(tz => tz.Offset), nameof(Id.Core.Data.Entities.TimeZone.TimeZoneId), nameof(Id.Core.Data.Entities.TimeZone.LongName), model.Timezone);
            }

            var grants = await this.Interaction.GetAllUserGrantsAsync();

            foreach (var grant in grants)
            {
                var client = await this.ClientStore.FindClientByIdAsync(grant.ClientId);

                if (client != null)
                {
                    var identityResources = await this.resourceStore.FindResourcesByScopeAsync(grant.Scopes);

                    model.Grants.Add(new GrantViewModel
                    {
                        ClientId = client.ClientId,
                        ClientName = client.ClientName ?? client.ClientId,
                        ClientLogoUrl = client.LogoUri,
                        ClientUrl = client.ClientUri,
                        Created = grant.CreationTime,
                        Expires = grant.Expiration,
                        IdentityGrantNames = identityResources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                        ApiGrantNames = identityResources.ApiResources.Select(x => x.DisplayName ?? x.Name).ToArray()
                    });
                }
            }

            return model;
        }

        /// <summary>
        /// This method is used to populate a profile model with values from user claims.
        /// </summary>
        /// <param name="model">Contains the model to populate.</param>
        /// <param name="claims">Contains a list of user claims.</param>
        private void PopulateClaims(ManageUserProfileModel model, IList<Claim> claims)
        {
            if (claims != null && claims.Any())
            {
                claims.ToList().ForEach(claim =>
                {
                    switch (claim.Type)
                    {
                        case JwtClaimTypes.Name:
                            model.NickName = claim.Value;
                            break;

                        case JwtClaimTypes.GivenName:
                            model.FirstName = claim.Value;
                            break;

                        case JwtClaimTypes.MiddleName:
                            model.MiddleName = claim.Value;
                            break;

                        case JwtClaimTypes.FamilyName:
                            model.LastName = claim.Value;
                            break;

                        case JwtClaimTypes.WebSite:
                            model.Website = claim.Value;
                            break;

                        case JwtClaimTypes.Locale:
                            model.Locale = claim.Value;
                            break;

                        case JwtClaimTypes.PhoneNumber:
                            model.PhoneNumber = claim.Value;
                            break;

                        case JwtClaimTypes.ZoneInfo:
                            model.Timezone = claim.Value;
                            break;
                    }
                });
            }
        }

        #endregion

        #region Private Login Methods

        /// <summary>
        /// This method is used to build the login view model for the login page.
        /// </summary>
        /// <param name="model">Contains the <see cref="LoginInputModel" /> model data.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns a new instance of the <see cref="LoginViewModel" /> class.</returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model, CancellationToken cancellationToken)
        {
            var vm = await this.BuildLoginViewModelAsync(model.ReturnUrl, cancellationToken);
            vm.UserName = model.UserName;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        /// <summary>
        /// This method is used to build the login view model for the login page.
        /// </summary>
        /// <param name="returnUrl">Contains the URL to redirect to after login.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns a new instance of the <see cref="LoginViewModel" /> class.</returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl, CancellationToken cancellationToken)
        {
            LoginViewModel loginViewModel;
            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, returnUrl, cancellationToken);

            var authRequest = await this.Interaction.GetAuthorizationContextAsync(returnUrl);

            // if just working with the local login identity provider...
            if (authRequest?.IdP != null && await this.SchemeProvider.GetSchemeAsync(authRequest.IdP) != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                loginViewModel = this.CreateLoginViewModel(
                    this.Context.Settings.Account.AllowRememberLogin,
                    false,
                    returnUrl,
                    authRequest?.LoginHint,
                    tenantConfig,
                    new[] { new ExternalProviderModel { AuthenticationScheme = authRequest.IdP } });
            }
            else
            {
                // this will render the login view model with all available schemes (external providers) included.
                var schemes = await this.SchemeProvider.GetAllSchemesAsync();

                // get providers from schemes.
                List<ExternalProviderModel> providers = schemes
                    .Where(x => x.DisplayName != null ||
                                x.Name.Equals(this.Context.Settings.Account.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                    .Select(x => new ExternalProviderModel
                    {
                        DisplayName = x.DisplayName,
                        AuthenticationScheme = x.Name
                    }).ToList();

                bool allowClientLocal = true;

                // if a tenant was defined...
                if (authRequest?.Tenant != null)
                {
                    // and a client is found too...
                    if (authRequest.Client != null)
                    {
                        // get configuration from the client info...
                        allowClientLocal = authRequest.Client.EnableLocalLogin;

                        // get any providers defined for the client...
                        if (authRequest.Client.IdentityProviderRestrictions != null && authRequest.Client.IdentityProviderRestrictions.Any())
                        {
                            providers = providers.Where(provider => authRequest.Client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                        }
                    }
                }

                // build the view model
                loginViewModel = this.CreateLoginViewModel(
                    this.Context.Settings.Account.AllowRememberLogin,
                    allowClientLocal && this.Context.Settings.Account.AllowLocalLogin,
                    returnUrl,
                    authRequest?.LoginHint,
                    tenantConfig,
                    providers);
            }

            return loginViewModel;
        }

        /// <summary>
        /// This method is used to create a new <see cref="LoginViewModel" /> to return to the login page.
        /// </summary>
        /// <param name="allowRememberLogin">Contains a value indicating whether the user can be remembered via cookie.</param>
        /// <param name="enableLocalLogin">Contains a value indicating whether local login is enabled.</param>
        /// <param name="returnUrl">Contains the return Url to redirect to after authentication.</param>
        /// <param name="userName">Contains the user name hint.</param>
        /// <param name="tenantConfig">Contains any related tenant configr record related to a tenant identifier.</param>
        /// <param name="providers">Contains an enumerated list of external providers.</param>
        /// <returns>Returns a new <see cref="LoginViewModel" /> object.</returns>
        private LoginViewModel CreateLoginViewModel(bool allowRememberLogin, bool enableLocalLogin, string returnUrl, string userName, TenantConfig tenantConfig, IEnumerable<ExternalProviderModel> providers)
        {
            string placeholderText = string.Empty;

            switch (this.Context.Settings.Account.RequiredLoginIdentifier)
            {
                case LoginIdentifierMethod.Email:
                    placeholderText = Resources.EmailText;
                    break;

                case LoginIdentifierMethod.UserName:
                    placeholderText = Resources.UserNameText;
                    break;

                case LoginIdentifierMethod.UserNameOrEmail:
                    placeholderText = Resources.IdentifierPlaceholderEmailOrUserNameText;
                    break;

                case LoginIdentifierMethod.UserNameOrEmailOrPhone:
                    placeholderText = Resources.IdentifierPlaceholderEmailOrUserNameOrPhoneText;
                    break;
            }

            return new LoginViewModel
            {
                UserNamePlaceholder = placeholderText,
                AllowRememberLogin = allowRememberLogin,
                AllowRegistration = this.Context.Settings.Account.AllowRegistration,
                EnableLocalLogin = enableLocalLogin,
                ReturnUrl = returnUrl,
                UserName = userName,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName,
                ExternalProviders = providers.ToList(),
                Version = this.Context.Settings.Version
            };
        }

        #endregion

        #region Private Logout Methods

        /// <summary>
        /// This method is used to build the logout view model for the logout page.
        /// </summary>
        /// <param name="model">Contains the logout view model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns a new instance of the <see cref="LogoutViewModel" /> class.</returns>
        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(LogoutInputModel model, CancellationToken cancellationToken)
        {
            model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, model.ReturnUrl, cancellationToken);

            LogoutViewModel vm = new LogoutViewModel
            {
                LogoutId = model.LogoutId,
                ShowLogoutPrompt = this.Context.Settings.Account.ShowLogoutPrompt,
                ReturnUrl = model.ReturnUrl,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null && !string.IsNullOrEmpty(tenantConfig.LogoUrl) ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName
            };

            if (this.User?.Identity.IsAuthenticated == false)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
            }
            else
            {
                var context = await this.Interaction.GetLogoutContextAsync(model.LogoutId);

                if (context?.ShowSignoutPrompt == false)
                {
                    // it's safe to automatically sign-out
                    vm.ShowLogoutPrompt = false;
                }
            }

            // show the logout prompt. this prevents attacks where the user is automatically signed out by another malicious web page.
            return vm;
        }

        /// <summary>
        /// This method is used to build the logged out view model for the logged out page.
        /// </summary>
        /// <param name="model">Contains the logout input view model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns a new instance of the <see cref="LoggedOutViewModel" /> class.</returns>
        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(LogoutInputModel model, CancellationToken cancellationToken)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await this.Interaction.GetLogoutContextAsync(model.LogoutId);

            model.ReturnUrl = this.CheckReturnUrl(model.ReturnUrl);

            TenantConfig tenantConfig = await this.Interaction.FindTenantConfigAsync(this.DataContext, this.DistributedCache, model.ReturnUrl, cancellationToken);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = this.Context.Settings.Account.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri ?? model.ReturnUrl,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = model.LogoutId,
                TenantName = tenantConfig != null ? tenantConfig.Name : string.Empty,
                LoginLogoImageUrl = tenantConfig != null && !string.IsNullOrEmpty(tenantConfig.LogoUrl) ? tenantConfig.LogoUrl : ControllerDefaults.DefaultLogoImageName
            };

            if (this.User?.Identity.IsAuthenticated == true)
            {
                var idp = this.User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await this.HttpContext.GetSchemeSupportsSignOutAsync(idp);

                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one this captures necessary info from the current logged in user before
                            // we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await this.Interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        #endregion

        #region Private Registration Methods

        /// <summary>
        /// Finds the external providers asynchronous.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns>Returns a list of <see cref="ExternalProviderModel" /> found.</returns>
        private async Task<List<ExternalProviderModel>> FindExternalProvidersAsync(string returnUrl)
        {
            var authRequest = await this.Interaction.GetAuthorizationContextAsync(returnUrl);
            var schemes = await this.SchemeProvider.GetAllSchemesAsync();

            List<ExternalProviderModel> providers = schemes
                .Where(x => x.DisplayName != null || x.Name.Equals(this.Context.Settings.Account.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                .Select(x => new ExternalProviderModel
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            bool allowClientLocal = true;

            if (authRequest?.Tenant != null)
            {
                if (authRequest.Client != null)
                {
                    allowClientLocal = authRequest.Client.EnableLocalLogin;

                    if (authRequest.Client.IdentityProviderRestrictions != null && authRequest.Client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => authRequest.Client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return providers;
        }

        #endregion
    }
}