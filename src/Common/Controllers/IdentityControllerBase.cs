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

namespace Bastille.Id.Server.Core.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Data;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Core.Extensions;
    using Bastille.Id.Core.Logging;
    using Bastille.Id.Models;
    using Bastille.Id.Models.Logging;
    using Bastille.Id.Server.Controllers;
    using Bastille.Id.Server.Core.Common;
    using Bastille.Id.Server.Core.Configuration;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Http.Extensions;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Talegen.AspNetCore.Web.Extensions;
    using Talegen.Common.Core.Extensions;
    using Talegen.Common.Messaging;
    using Talegen.Common.Messaging.Models;
    using Talegen.Common.Messaging.Senders;
    using Vasont.AspnetCore.RedisClient;
    using Resources = Properties.Resources;

    /// <summary>
    /// This is a base controller implementation within the application. It provides several additional properties and methods to support pages within the
    /// identity server application.
    /// </summary>
    public abstract class IdentityControllerBase : Controller
    {
        #region Private Fields

        /// <summary>
        /// Contains an instance of the security log service.
        /// </summary>
        private readonly Lazy<AuditLogService> securityLogService;

        /// <summary>
        /// Contains a value indicating whether or not the check for IsManagerForOrganizations has been made.
        /// </summary>
        private bool hasQueriedForManager;

        /// <summary>
        /// Contains the value indicating whether or not the user is a manager of an organization.
        /// </summary>
        private bool managerForOrganizations;

        /// <summary>
        /// The current user identifier.
        /// </summary>
        private Guid currentUserId;

        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityControllerBase" /> class. Values are injected by the web application.
        /// </summary>
        /// <param name="appSettings">Contains an instance of the application settings.</param>
        /// <param name="distributedCache">Contains distributed cache instance.</param>
        /// <param name="appContext">Contains an instance of the application database context.</param>
        /// <param name="userManager">Contains an instance of the identity user manager.</param>
        /// <param name="signInManager">Contains an instance of the identity sign-in manager.</param>
        /// <param name="interaction">Contains an instance of the identity server interaction interfaces.</param>
        /// <param name="clientStore">Contains an instance of the identity server client store.</param>
        /// <param name="schemeProvider">Contains an instance of the identity server authentication scheme provider.</param>
        /// <param name="events">Contains an instance of the identity server events service.</param>
        /// <param name="messageSender">Contains an instance of the messaging sender.</param>
        /// <param name="hostingEnvironment">Contains an instance of the hosting environment.</param>
        /// <param name="logger">Contains an instance of the associated logger.</param>
        protected IdentityControllerBase(IOptions<ApplicationSettings> appSettings, IAdvancedDistributedCache distributedCache, ApplicationContext<ApplicationSettings> appContext,
            UserManager<User> userManager, SignInManager<User> signInManager, IIdentityServerInteractionService interaction, IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider, IEventService events, IMessageSender messageSender, IWebHostEnvironment hostingEnvironment, ILogger<IdentityControllerBase> logger)
        {
            this.ApplicationSettings = appSettings?.Value;
            this.HostEnvironment = hostingEnvironment;

            // setup working folder if none specified
            if (hostingEnvironment != null && string.IsNullOrWhiteSpace(this.ApplicationSettings.Storage.RootPath))
            {
                // working folder will reside in the main application folder by default.
                this.ApplicationSettings.Storage.RootPath = Path.Combine(hostingEnvironment.ContentRootPath, this.ApplicationSettings.Advanced.AppDataSubFolderName);
            }

            this.DistributedCache = distributedCache;
            this.Context = appContext;
            this.UserManager = userManager;
            this.SignInManager = signInManager;
            this.Interaction = interaction;
            this.ClientStore = clientStore;
            this.SchemeProvider = schemeProvider;
            this.Events = events;
            this.MessageSender = messageSender;
            this.Logger = logger;

            // create an instance of the security log service.
            this.securityLogService = new Lazy<AuditLogService>(new AuditLogService(appContext.DataContext));
        }

        #region Temp Data Properties

        /// <summary>
        /// Gets or sets the status message temp data.
        /// </summary>
        [TempData]
        public string StatusMessage { get; set; }

        /// <summary>
        /// Gets or sets the status message type.
        /// </summary>
        public StatusMessageResultType StatusMessageType
        {
            get
            {
                StatusMessageResultType result = StatusMessageResultType.Info;

                string value = this.TempData.Peek("StatusMessageResultType") as string;

                if (!string.IsNullOrEmpty(value))
                {
                    result = value.ToEnum<StatusMessageResultType>();
                }

                return result;
            }

            set => this.TempData["StatusMessageResultType"] = value.ToString();
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets the environment.
        /// </summary>
        /// <value>The environment.</value>
        public IWebHostEnvironment HostEnvironment { get; }

        /// <summary>
        /// Gets the context.
        /// </summary>
        /// <value>The context.</value>
        public ApplicationContext<ApplicationSettings> Context { get; }

        /// <summary>
        /// Gets the distributed cache.
        /// </summary>
        /// <value>The distributed cache.</value>
        public IAdvancedDistributedCache DistributedCache { get; }

        /// <summary>
        /// Gets an instance of the application settings.
        /// </summary>
        public ApplicationSettings ApplicationSettings { get; }

        /// <summary>
        /// Gets an instance of the application database context.
        /// </summary>
        public ApplicationDbContext DataContext => this.Context.DataContext;

        /// <summary>
        /// Gets an instance of the identity user manager.
        /// </summary>
        public UserManager<User> UserManager { get; }

        /// <summary>
        /// Gets an instance of the identity sign-in manager.
        /// </summary>
        public SignInManager<User> SignInManager { get; }

        /// <summary>
        /// Gets an instance of the messaging sender.
        /// </summary>
        public IMessageSender MessageSender { get; }

        /// <summary>
        /// Gets an instance of the associated logger.
        /// </summary>
        public Microsoft.Extensions.Logging.ILogger Logger { get; }

        #region IdentityServer4 Properties

        /// <summary>
        /// Gets an instance of the identity server interaction interfaces.
        /// </summary>
        public IIdentityServerInteractionService Interaction { get; }

        /// <summary>
        /// Gets an instance of the identity server client store.
        /// </summary>
        public IClientStore ClientStore { get; }

        /// <summary>
        /// Gets an instance of the identity server authentication scheme provider.
        /// </summary>
        public IAuthenticationSchemeProvider SchemeProvider { get; }

        /// <summary>
        /// Gets an instance of the identity server events service.
        /// </summary>
        public IEventService Events { get; }

        #endregion

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <value>The current user.</value>
        public User CurrentUser
        {
            get
            {
                return AsyncHelper.RunSync(() => this.UserManager.GetUserAsync(this.User)); ;
            }
        }

        /// <summary>
        /// Gets the current user identity value.
        /// </summary>
        public Guid CurrentUserId
        {
            get
            {
                if (this.currentUserId == Guid.Empty && this.User != null)
                {
                    // get subject
                    string id = this.User.GetUserId();
                    this.currentUserId = !string.IsNullOrEmpty(id) ? new Guid(id) : this.UserManager.GetUserId(this.User).ToGuid();
                }

                return this.currentUserId;
            }
        }

        /// <summary>
        /// Gets the optional current user identifier.
        /// </summary>
        /// <value>The optional current user identifier.</value>
        public Guid? OptionalCurrentUserId
        {
            get
            {
                Guid? result = null;

                if (this.CurrentUserId != Guid.Empty)
                {
                    result = this.CurrentUserId;
                }

                return result;
            }
        }

        /// <summary>
        /// Gets the current user name.
        /// </summary>
        public string CurrentUserName => this.UserManager.GetUserName(this.User);

        /// <summary>
        /// Gets the current client IP address.
        /// </summary>
        public string ClientAddress => this.HttpContext?.Connection?.RemoteIpAddress.ToString();

        /// <summary>
        /// Gets the current request URI.
        /// </summary>
        public Uri CurrentUri => new Uri(UriHelper.BuildAbsolute(this.Request.Scheme, this.Request.Host, this.Request.Path));

        /// <summary>
        /// Gets a lazy-loaded instance of the security log service.
        /// </summary>
        public AuditLogService AuditLog => this.securityLogService.Value;

        /// <summary>
        /// Gets the current user time zone information. If the user has no time zone claim, time zone is set to a default of UTC.
        /// </summary>
        /// <returns>Returns a value indicating the time zone information for the logged-in user.</returns>
        public string CurrentUserTimezone
        {
            get
            {
                return this.User.GetTimeZone() ?? "Etc/UTC";
            }
        }

        /// <summary>
        /// Gets the current user locale information. If the user has no time zone claim, locale is set to a default English
        /// </summary>
        /// <returns>Returns a value indicating the locale for the logged-in user.</returns>
        public string CurrentUserLocale
        {
            get
            {
                return this.User.GetLocale() ?? "en-US";
            }
        }

        /// <summary>
        /// Gets a value indicating whether the current user has organization manager privileges for any of the organizations a user is a member.
        /// </summary>
        /// <returns>Returns a value indicating whether the user manages any organizations.</returns>
        public bool IsOwnerForAnyGroup
        {
            get
            {
                if (!this.hasQueriedForManager)
                {
                    this.hasQueriedForManager = true;
                    this.managerForOrganizations = this.DataContext.GroupUsers
                        .AsNoTracking()
                        .Any(ou => ou.UserId == this.CurrentUserId && ou.Group.OwnerUserId == this.CurrentUserId);
                }

                return this.managerForOrganizations;
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// This method is executed on every action request.
        /// </summary>
        /// <param name="context">Contains the action context.</param>
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            this.ViewData["ShowDiagnostics"] = this.ApplicationSettings.Advanced.ShowDiagnostics;
            this.ViewData["IsOwner"] = this.IsOwnerForAnyGroup;

            base.OnActionExecuting(context);
        }

        /// <summary>
        /// This method is used to check if the current user has organization manager privileges
        /// </summary>
        /// <param name="organizationId">Contains the identity of the organization to check.</param>
        /// <returns>Returns true if user is a manager for the specified organization.</returns>
        public bool IsGroupOwner(Guid organizationId)
        {
            bool userIsManager = false;

            if (organizationId != Guid.Empty)
            {
                // Checks if the user is a manager to the provided organization
                userIsManager = this.DataContext.Groups
                    .AsNoTracking()
                    .Any(o => o.OwnerUserId == this.CurrentUserId && o.GroupId == organizationId);
            }

            return userIsManager;
        }

        /// <summary>
        /// This method is used to return an access denied error page.
        /// </summary>
        /// <param name="message">An optional security log message.</param>
        /// <param name="securityEvent">Optional security event.</param>
        /// <returns>Returns an action result to the access denied page.</returns>
        [HttpGet]
        public async Task<IActionResult> AccessDenied(string message = "", AuditEvent securityEvent = AuditEvent.Validation)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                await this.AuditLog.LogAsync(securityEvent, AuditResult.Fail, this.ClientAddress, message);
            }

            return this.View("~/Views/AccessDenied.cshtml");
        }

        /// <summary>
        /// This method is used to add model errors to the status message property.
        /// </summary>
        /// <param name="statusMessageType">Contains the status message type.</param>
        public void AddModelErrorsToStatus(StatusMessageResultType statusMessageType)
        {
            var errors = this.ModelState.Where(s => s.Value.Errors.Any()).Select(s => s.Value).ToList();
            StringBuilder builder = new StringBuilder();

            if (errors.Any())
            {
                builder.Append("<ul>");

                errors.SelectMany(modelItem => modelItem.Errors).ToList().ForEach(err =>
                {
                    builder.Append("<li>");
                    builder.Append(err.ErrorMessage);
                    builder.Append("</li>");
                });

                builder.Append("</ul>");
            }

            this.StatusMessage = builder.ToString();
            this.StatusMessageType = statusMessageType;
        }

        /// <summary>
        /// This method is used to add identity result errors to the model error manager.
        /// </summary>
        /// <param name="result">Contains the identity result that contains errors.</param>
        public void AddErrors(IdentityResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(string.Empty, error.Description);
            }

            this.AddModelErrorsToStatus(StatusMessageResultType.Warning);
        }

        /// <summary>
        /// This method is used to redirect to a local URL.
        /// </summary>
        /// <param name="returnUrl">Contains the return url to redirect to.</param>
        /// <returns>Returns a new action result to the local URL.</returns>
        public IActionResult RedirectToLocal(string returnUrl)
        {
            IActionResult returnResult;

            if (this.Url.IsLocalUrl(returnUrl))
            {
                returnResult = this.Redirect(returnUrl);
            }
            else
            {
                returnResult = this.RedirectToAction(nameof(AccountController.Index), "Home");
            }

            return returnResult;
        }

        /// <summary>
        /// This method is used to build an absolute URL to a specified path.
        /// </summary>
        /// <param name="path">Contains the path to include in the absolute URL.</param>
        /// <returns>Returns the absolute URL.</returns>
        public string BuildAbsoluteUrl(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            string baseUrl = string.Format(CultureInfo.InvariantCulture, "{0}://{1}/", this.HttpContext.Request.Scheme, this.HttpContext.Request.Host);

            return path.Contains("~/", StringComparison.InvariantCultureIgnoreCase) ? path.Replace("~/", baseUrl, true, CultureInfo.InvariantCulture) : baseUrl + path;
        }

        /// <summary>
        /// Checks if the redirect URI is for a native client.
        /// </summary>
        /// <returns></returns>
        public bool IsNativeClient(AuthorizationRequest context)
        {
            return !context.RedirectUri.StartsWith("https", StringComparison.Ordinal) && !context.RedirectUri.StartsWith("http", StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks the return URL.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns>Returns the URL or a base redirect URL if the return URL value is invalid.</returns>
        public string CheckReturnUrl(string returnUrl)
        {
            string returnValue = returnUrl;

            if (string.IsNullOrWhiteSpace(returnValue) || !(this.Interaction.IsValidReturnUrl(returnValue) || this.Url.IsLocalUrl(returnValue)))
            {
                returnValue = this.BuildAbsoluteUrl(ControllerDefaults.BaseRedirectUrl);
            }

            return returnValue;
        }

        /// <summary>
        /// Loadings the page.
        /// </summary>
        /// <param name="viewName">Name of the view.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns></returns>
        public IActionResult RedirectToView(string viewName, string redirectUri)
        {
            this.HttpContext.Response.StatusCode = StatusCodes.Status200OK;
            this.HttpContext.Response.Headers["Location"] = string.Empty;

            return this.View(viewName, new { RedirectUrl = redirectUri });
        }

        ///// <summary>
        ///// Finds the tenant configuration.
        ///// </summary>
        ///// <returns>Returns a <see cref="TenantConfig" /> object if found.</returns>
        //public async Task<TenantConfig> FindTenantConfigAsync(string returnUrl)
        //{
        //    var authRequest = await this.Interaction.GetAuthorizationContextAsync(returnUrl);
        //    TenantConfig tenantConfig = null;

        // if (authRequest != null) { // see if there is an ACR of tenant:name_of_tenant string tenantKey = authRequest.Tenant; if
        // (!string.IsNullOrWhiteSpace(tenantKey)) { // return the value after tenant: prefix tenantKey = tenantKey.After(':'); } // if we found the domain key
        // out of the acr values... if (!string.IsNullOrWhiteSpace(tenantKey)) { // find an organization information by domain key tenantConfig = await
        // this.Context.DataContext.TenantConfigs .FirstOrDefaultAsync(ap => ap.TenantKey == tenantKey || ap.TenantId.ToString() == tenantKey); } }

        //    return tenantConfig;
        //}

        #endregion

        #region Protected Support Methods

        #region Messaging Support Methods

        /// <summary>
        /// This method is used send a reset password link via e-mail to the user.
        /// </summary>
        /// <param name="redirectUrl">Contains the reset link.</param>
        /// <param name="user">Contains the user to send the link to.</param>
        /// <param name="subject">Contains the subject of the e-mail message.</param>
        /// <param name="emailTemplateName">Contains the name of the e-mail template to use.</param>
        /// <param name="messagingContext">Contains optional email context settings.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns the task result.</returns>
        protected async Task SendAccountEmailAsync(string redirectUrl, User user, string subject, string emailTemplateName, MessagingContext messagingContext = null, CancellationToken cancellationToken = default)
        {
            if (messagingContext == null)
            {
                messagingContext = new MessagingContext
                {
                    From = this.Context.Settings.Messaging.FromAddress
                };
            }

            // create a dictionary of token values used to replace tokens with values in the message body.
            Dictionary<string, string> tokensList = new Dictionary<string, string>(messagingContext.TokenValues);
            MessageUser emailUser = await user.ToMessageUserAsync(this.Context.DataContext, $"https://{this.CurrentUri.Host}");
            tokensList.InitializeBaseTokens(this.CurrentUri, emailUser);

            // add link for reset
            tokensList.Add(TemplateTokens.Link, redirectUrl);

            var templates = await this.DataContext.Templates
                .Where(t => t.TemplateKey.StartsWith($"{emailTemplateName}_{emailUser.Locale}_"))
                .Select(t => new Talegen.Common.Messaging.Templates.Template
                {
                    TemplateId = t.TemplateId,
                    TemplateKey = t.TemplateKey,
                    TemplateType = t.TemplateType,
                    Content = t.Content
                })
                .ToListAsync(cancellationToken);

            // create the sender message
            SenderMessage senderMessage = MessageExtensions.CreateSenderMessage(
                new MessageSettingsModel
                {
                    From = this.Context.Settings.Messaging.FromAddress,
                    Subject = subject,
                    TemplateName = emailTemplateName,
                    To = new List<string>() { emailUser.Email },
                    ResourceManager = Id.Core.Properties.Resources.ResourceManager,
                    CultureInfoOverride = emailUser.CultureInfo,
                    Tokens = tokensList
                },
                templates);

            // send the message
            await this.MessageSender.SendMessageAsync(senderMessage, cancellationToken);
        }

        #endregion

        /// <summary>
        /// This method is used to set the selected menu on the portal application interface.
        /// </summary>
        /// <param name="menuKey">Contains the menu key to highlight.</param>
        protected void SetMenu(string menuKey)
        {
            this.ViewData["MenuSelected"] = menuKey;
        }

        /// <summary>
        /// This method is used to redirect to the return Url.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        /// <param name="validReturnUrl">if set to <c>true</c> [valid return URL].</param>
        /// <param name="isLocalUrl">if set to <c>true</c> [is local URL].</param>
        /// <returns>Returns a new action result to the redirect URL.</returns>
        protected IActionResult RedirectToReturnUrl(string returnUrl, bool validReturnUrl, bool isLocalUrl)
        {
            IActionResult returnResult;

            if (isLocalUrl || validReturnUrl)
            {
                returnResult = this.Redirect(returnUrl);
            }
            else
            {
                returnResult = this.RedirectToAction(nameof(AccountController.Index), ControllerDefaults.AccountControllerName);
            }

            return returnResult;
        }

        #endregion
    }
}