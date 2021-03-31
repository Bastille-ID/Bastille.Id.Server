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

namespace Bastille.Id.Server.Core.Security.Models
{
    /// <summary>
    /// This class is the logged out view model.
    /// </summary>
    public class LoggedOutViewModel
    {
        /// <summary>
        /// Gets or sets the post logout redirect URL.
        /// </summary>
        public string PostLogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the client name.
        /// </summary>
        public string ClientName { get; set; }

        /// <summary>
        /// Gets or sets the sign out frame URL.
        /// </summary>
        public string SignOutIframeUrl { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the browser is automatically redirected after sign out.
        /// </summary>
        public bool AutomaticRedirectAfterSignOut { get; set; }

        /// <summary>
        /// Gets or sets the logout identity.
        /// </summary>
        public string LogoutId { get; set; }

        /// <summary>
        /// Gets a value indicating whether the external sign out is triggered.
        /// </summary>
        public bool TriggerExternalSignout => this.ExternalAuthenticationScheme != null;

        /// <summary>
        /// Gets or sets the external authentication scheme.
        /// </summary>
        public string ExternalAuthenticationScheme { get; set; }

        /// <summary>
        /// Gets or sets the Tenant name.
        /// </summary>
        public string TenantName { get; set; }

        /// <summary>
        /// Gets or sets the application name.
        /// </summary>
        public string LoginApplicationName { get; set; }

        /// <summary>
        /// Gets or sets the tenant logo image.
        /// </summary>
        public string LoginLogoImageUrl { get; set; }
    }
}