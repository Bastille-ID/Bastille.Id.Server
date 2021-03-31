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
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Text.Encodings.Web;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Core.Security;
    using Bastille.Id.Server.Core.Common;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Controllers;
    using Bastille.Id.Server.Core.Security.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Serilog;
    using Talegen.Common.Messaging.Senders;
    using Vasont.AspnetCore.RedisClient;
    using Resources = Properties.Resources;

    /// <summary>
    /// This class contains controller endpoints for authenticator related calls.
    /// </summary>
    /// <seealso cref="IdentityControllerBase" />
    [AllowAnonymous]
    public class AuthenticatorController : IdentityControllerBase
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
        /// Initializes a new instance of the <see cref="AuthenticatorController" /> class.
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
        public AuthenticatorController(IOptions<ApplicationSettings> appSettings, IAdvancedDistributedCache distributedCache, ApplicationContext<ApplicationSettings> appContext,
            UserManager<User> userManager, SignInManager<User> signInManager, IIdentityServerInteractionService interaction, IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider, IEventService events, IMessageSender messageSender, IWebHostEnvironment hostingEnvironment,
            IResourceStore resourceStore, ILogger<AuthenticatorController> logger)
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

        #region Public Properties

        /// <summary>
        /// Gets or sets the recovery codes array.
        /// </summary>
        [TempData]
        public string[] RecoveryCodes { get; set; }

        #endregion

        /// <summary>
        /// This controller method is used to render the two-factor authentication page.
        /// </summary>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the view results.</returns>
        public async Task<IActionResult> Enable(CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.RedirectToAction(nameof(AccountController.Index), ControllerDefaults.AccountControllerName);

            switch (this.ApplicationSettings.Account.TwoFactor.Method)
            {
                case TwoFactorMethod.TOTP:

                    var user = await this.UserManager.GetUserAsync(this.User);

                    if (user != null)
                    {
                        await this.LoadSharedKeyAndQrCodeUriAsync(user);
                        actionResult = this.View();
                    }
                    else
                    {
                        actionResult = this.NotFound(string.Format(CultureInfo.CurrentCulture, Id.Core.Properties.Resources.ErrorUserNotFoundText));
                    }

                    break;

                case TwoFactorMethod.SMS:
                    throw new NotSupportedException();
                case TwoFactorMethod.None:
                    break;
            }

            return actionResult;
        }

        /// <summary>
        /// This controller method executes the authenticator enabling code.
        /// </summary>
        /// <param name="model">Contains the input model.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the view results.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable(LoginTwoFactorViewModel model, CancellationToken cancellationToken)
        {
            IActionResult actionResult = this.RedirectToAction(nameof(AccountController.Index), ControllerDefaults.AccountControllerName);

            switch (this.Context.Settings.Account.TwoFactor.Method)
            {
                case TwoFactorMethod.TOTP:
                    User userFound = await this.UserManager.GetUserAsync(this.User);

                    if (userFound != null)
                    {
                        if (this.ModelState.IsValid)
                        {
                            // Strip spaces and hypens
                            string verificationCode = model.Code.Replace(" ", string.Empty, StringComparison.InvariantCulture).Replace("-", string.Empty, StringComparison.InvariantCulture);

                            // validate authenticator token
                            if (await this.UserManager.VerifyTwoFactorTokenAsync(userFound, this.UserManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode))
                            {
                                await this.UserManager.SetTwoFactorEnabledAsync(userFound, true);
                                Log.Information(Resources.AuthenticatorAppVerifiedText, userFound.UserName, userFound.Id);
                                this.StatusMessage = Resources.AuthenticatorAppVerifiedText;

                                if (await this.UserManager.CountRecoveryCodesAsync(userFound) == 0)
                                {
                                    var recoveryCodes = await this.UserManager.GenerateNewTwoFactorRecoveryCodesAsync(userFound, 10);
                                    this.RecoveryCodes = recoveryCodes.ToArray();
                                    actionResult = this.RedirectToAction(nameof(this.ShowRecoveryCodes));
                                }
                                else
                                {
                                    actionResult = this.RedirectToAction(nameof(AccountController.TwoFactorLogin), ControllerDefaults.AccountControllerName);
                                }
                            }
                            else
                            {
                                this.ModelState.AddModelError(nameof(model.Code), Resources.VerificationCodeInvalidText);
                                await this.LoadSharedKeyAndQrCodeUriAsync(userFound);
                                actionResult = this.View(model);
                            }
                        }
                        else
                        {
                            await this.LoadSharedKeyAndQrCodeUriAsync(userFound);
                            actionResult = this.View(model);
                        }
                    }
                    else
                    {
                        actionResult = this.NotFound(string.Format(CultureInfo.CurrentCulture, Id.Core.Properties.Resources.ErrorUserNotFoundText));
                    }
                    break;

                case TwoFactorMethod.SMS:
                    throw new NotSupportedException();
                case TwoFactorMethod.None:
                    break;
            }

            return actionResult;
        }

        /// <summary>
        /// Shows the recovery codes.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult ShowRecoveryCodes()
        {
            IActionResult actionResult = this.View();

            if (this.RecoveryCodes == null || this.RecoveryCodes.Length == 0)
            {
                actionResult = this.RedirectToAction(nameof(AccountController.TwoFactorLogin));
            }

            return actionResult;
        }

        #region Private Methods

        /// <summary>
        /// This method is used to generate and load a shared key and QR code Uri for two-factor authentication.
        /// </summary>
        /// <param name="user">Contains the user to load data for.</param>
        /// <returns>Returns a task result.</returns>
        private async Task LoadSharedKeyAndQrCodeUriAsync(User user)
        {
            // Load the authenticator key & QR code URI to display on the form
            var unformattedKey = await this.UserManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(unformattedKey))
            {
                await this.UserManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await this.UserManager.GetAuthenticatorKeyAsync(user);
            }

            this.ViewBag.SharedKey = FormatKey(unformattedKey);
            this.ViewBag.AuthenticatorUri = GenerateQrCodeUri(await this.UserManager.GetEmailAsync(user), unformattedKey);
        }

        /// <summary>
        /// This method is used to format an unformatted key.
        /// </summary>
        /// <param name="unformattedKey">Contains the unformatted key to format.</param>
        /// <returns>Returns the formatted key.</returns>
        private static string FormatKey(string unformattedKey)
        {
            StringBuilder result = new StringBuilder();
            int currentPosition = 0;

            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }

            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey[currentPosition..]);
            }

            return result.ToString().ToLowerInvariant();
        }

        /// <summary>
        /// This method is used to generate a QR code URI string.
        /// </summary>
        /// <param name="email">Contains the user's email address.</param>
        /// <param name="unformattedKey">Contains the unformatted key to encode.</param>
        /// <returns>Returns the QR code Uri string.</returns>
        private static string GenerateQrCodeUri(string email, string unformattedKey)
        {
            UrlEncoder urlEncoder = UrlEncoder.Default;

            return string.Format(CultureInfo.InvariantCulture,
                ControllerDefaults.AuthenticatorUriFormat,
                urlEncoder.Encode(Resources.ApplicationName),
                urlEncoder.Encode(email),
                unformattedKey);
        }

        #endregion
    }
}