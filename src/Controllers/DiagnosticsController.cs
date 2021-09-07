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
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Controllers;
    using Bastille.Id.Server.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Talegen.Common.Messaging.Senders;
    using Vasont.AspnetCore.RedisClient;

    /// <summary>
    /// This class contains server diagnostic controller methods.
    /// </summary>
    [Authorize]
    public class DiagnosticsController : IdentityControllerBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DiagnosticsController" /> class.
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
        /// <param name="logger">The logger.</param>
        public DiagnosticsController(IOptions<ApplicationSettings> appSettings, IAdvancedDistributedCache distributedCache, ApplicationContext<ApplicationSettings> appContext,
            UserManager<User> userManager, SignInManager<User> signInManager, IIdentityServerInteractionService interaction, IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider, IEventService events, IMessageSender messageSender, IWebHostEnvironment hostingEnvironment,
            ILogger<ExternalController> logger)
            : base(appSettings, distributedCache, appContext, userManager, signInManager, interaction, clientStore, schemeProvider, events, messageSender, hostingEnvironment, logger)
        {
        }

        /// <summary>
        /// This controller method is used to return user diagnostic information.
        /// </summary>
        /// <returns>Returns the action result of the page view.</returns>
        public async Task<IActionResult> Index()
        {
            IActionResult actionResult = this.NotFound();

            if (this.ApplicationSettings.Advanced.ShowDiagnostics)
            {
                this.SetMenu("diagnostics");
                actionResult = this.View(new DiagnosticsViewModel(await this.HttpContext.AuthenticateAsync().ConfigureAwait(false)));
            }

            return actionResult;
        }
    }
}