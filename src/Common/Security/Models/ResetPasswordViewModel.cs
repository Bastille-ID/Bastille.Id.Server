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
    /// This class is the reset password view model.
    /// </summary>
    public class ResetPasswordViewModel
    {
        /// <summary>
        /// Gets or sets the e-mail address.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the new password.
        /// </summary>
        [Required]
        [RegularExpression(@"((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9 ])(?!.*\s).{8,20})", ErrorMessageResourceName = Id.Core.Properties.ResourceKeys.PromptPasswordRequirementsText, ErrorMessageResourceType = typeof(Id.Core.Properties.Resources))]
        [Display(Name = ResourceKeys.PasswordText, ResourceType = typeof(Resources))]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the confirm password.
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = ResourceKeys.ConfirmPasswordText, ResourceType = typeof(Resources))]
        [Compare(nameof(Password), ErrorMessageResourceName = Id.Core.Properties.ResourceKeys.PromptNewAndConfirmPasswordMustMatchText, ErrorMessageResourceType = typeof(Id.Core.Properties.Resources))]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// Gets or sets the reset password code.
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the return url of the login page.
        /// </summary>
        public string ReturnUrl { get; set; }

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
        /// Gets or sets a value indicating whether [enable local login].
        /// </summary>
        /// <value><c>true</c> if [enable local login]; otherwise, <c>false</c>.</value>
        public bool EnableLocalLogin { get; set; }
    }
}