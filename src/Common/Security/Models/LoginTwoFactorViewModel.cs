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
    /// This class represents the view model for the two-factor login page.
    /// </summary>
    public class LoginTwoFactorViewModel
    {
        /// <summary>
        /// Gets or sets the two factor code.
        /// </summary>
        [Required]
        [StringLength(7, ErrorMessageResourceName = ResourceKeys.StringLengthRequirementsText, ErrorMessageResourceType = typeof(Resources), MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = ResourceKeys.TwoFactorAuthenticationCodeText, ResourceType = typeof(Resources))]
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the device is remembered.
        /// </summary>
        [Display(Name = ResourceKeys.RememberDeviceText, ResourceType = typeof(Resources))]
        public bool RememberDevice { get; set; }

        /// <summary>
        /// Gets or sets the return url.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to remember the login.
        /// </summary>
        [Display(Name = ResourceKeys.RememberMeText, ResourceType = typeof(Resources))]
        public bool RememberLogin { get; set; }
    }
}