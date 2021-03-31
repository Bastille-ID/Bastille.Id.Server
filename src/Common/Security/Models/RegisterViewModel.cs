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
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Linq;
    using Bastille.Id.Models.Security;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Properties;
    using Talegen.AspNetCore.hCAPTCHA.Providers.Models;

    /// <summary>
    /// This class is the register view model.
    /// </summary>
    public class RegisterViewModel : IExternalProviderModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RegisterViewModel" /> class.
        /// </summary>
        public RegisterViewModel()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RegisterViewModel" /> class.
        /// </summary>
        /// <param name="response">The CAPTCHA response.</param>
        public RegisterViewModel(VerifyResponse response)
        {
            this.Response = response;
        }

        /// <summary>
        /// Gets or sets the login method.
        /// </summary>
        /// <value>The login method.</value>
        public LoginIdentifierMethod LoginMethod { get; set; } = LoginIdentifierMethod.Email;

        /// <summary>
        /// Gets or sets the e-mail address.
        /// </summary>
        [Required]
        [EmailAddress]
        [Display(Name = ResourceKeys.EmailText, ResourceType = typeof(Resources))]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user name
        /// </summary>
        [Display(Name = ResourceKeys.UserNameText, ResourceType = typeof(Resources))]
        public string UserName { get; set; }

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
        /// Gets or sets the mobile.
        /// </summary>
        /// <value>The mobile.</value>
        [Phone]
        [Display(Name = ResourceKeys.MobileText, ResourceType = typeof(Resources))]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        [Required]
        [StringLength(50, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 8)]
        [RegularExpression(@"((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,50})", ErrorMessageResourceName = Id.Core.Properties.ResourceKeys.PromptPasswordRequirementsText, ErrorMessageResourceType = typeof(Id.Core.Properties.Resources))]
        [DataType(DataType.Password)]
        [Display(Name = ResourceKeys.PasswordText, ResourceType = typeof(Resources))]
        public string Password { get; set; }

        /// <summary>
        /// Gets a CAPTCHA verification response.
        /// </summary>
        /// <value>The response.</value>
        public VerifyResponse Response { get; }

        /// <summary>
        /// Gets or sets a value indicating whether the user agrees to the terms agreement.
        /// </summary>
        /// <value>The user agrees to terms.</value>
        [Required]
        public string TermsAgree { get; set; }

        /// <summary>
        /// Gets or sets the confirm password.
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = ResourceKeys.ConfirmPasswordText, ResourceType = typeof(Resources))]
        [Compare(nameof(Password), ErrorMessageResourceName = Id.Core.Properties.ResourceKeys.PromptNewAndConfirmPasswordMustMatchText, ErrorMessageResourceType = typeof(Id.Core.Properties.Resources))]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [enable local login].
        /// </summary>
        /// <value><c>true</c> if [enable local login]; otherwise, <c>false</c>.</value>
        public bool EnableLocalLogin { get; set; }

        /// <summary>
        /// Gets or sets the sign-in identifier method.
        /// </summary>
        public string UserNamePlaceholder { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of <see cref="ExternalProviderModel" /> objects.
        /// </summary>
        public IEnumerable<ExternalProviderModel> ExternalProviders { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of visible <see cref="ExternalProviderModel" /> objects.
        /// </summary>
        public IEnumerable<ExternalProviderModel> VisibleExternalProviders => this.ExternalProviders?.Where(x => !string.IsNullOrWhiteSpace(x.DisplayName)) ?? new List<ExternalProviderModel>();

        /// <summary>
        /// Gets or sets the return url specified from the login page.
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
    }
}