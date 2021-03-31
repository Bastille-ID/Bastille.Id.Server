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
    using System.ComponentModel.DataAnnotations;
    using Bastille.Id.Server.Properties;

    /// <summary>
    /// This class is the external login view model.
    /// </summary>
    public class ExternalLoginViewModel
    {
        /// <summary>
        /// Gets or sets the user's first name.
        /// </summary>
        [Display(Name = ResourceKeys.FirstNameText, ResourceType = typeof(Resources))]
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the user's last name.
        /// </summary>
        [Display(Name = ResourceKeys.LastNameText, ResourceType = typeof(Resources))]
        public string LastName { get; set; }

        /// <summary>
        /// Gets or sets the model e-mail address.
        /// </summary>
        [Required]
        [Display(Name = ResourceKeys.EmailText, ResourceType = typeof(Resources))]
        [EmailAddress]
        public string Email { get; set; }

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

        /// <summary>
        /// Gets or sets the return URL.
        /// </summary>
        /// <value>The return URL.</value>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// Gets or sets the login provider.
        /// </summary>
        /// <value>The login provider.</value>
        public string LoginProvider { get; set; }
    }
}