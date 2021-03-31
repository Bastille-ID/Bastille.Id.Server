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
    using Bastille.Id.Core;
    using Bastille.Id.Models;
    using Bastille.Id.Server.Core.Common.Models;
    using Bastille.Id.Server.Properties;
    using Microsoft.AspNetCore.Mvc.Rendering;

    /// <summary>
    /// This class contains model information for updating a user profile.
    /// </summary>
    public class ManageUserProfileModel : BaseModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ManageUserProfileModel" /> class.
        /// </summary>
        public ManageUserProfileModel()
        {
            this.StatusType = StatusMessageResultType.Info;
        }

        /// <summary>
        /// Gets or sets e-mail address.
        /// </summary>
        [EmailAddress]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the e-mail address is confirmed.
        /// </summary>
        public bool IsEmailConfirmed { get; set; }

        /// <summary>
        /// Gets or sets the user's tenant name.
        /// </summary>
        public string TenantName { get; set; }

        /// <summary>
        /// Gets or sets the user phone number.
        /// </summary>
        [Phone]
        [Display(Name = ResourceKeys.MobileText, ResourceType = typeof(Resources))]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the user's first name.
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the user's last name.
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        /// Gets or sets the user's middle name.
        /// </summary>
        public string MiddleName { get; set; }

        /// <summary>
        /// Gets or sets the user's nick name.
        /// </summary>
        public string NickName { get; set; }

        /// <summary>
        /// Gets or sets the web site.
        /// </summary>
        [Url]
        public string Website { get; set; }

        /// <summary>
        /// Gets or sets the URL to the user's profile picture.
        /// </summary>
        public string PictureUrl { get; set; }

        /// <summary>
        /// Gets or sets the user's time zone.
        /// </summary>
        public string Timezone { get; set; }

        /// <summary>
        /// Gets or sets the user's preferred locale.
        /// </summary>
        public string Locale { get; set; }

        /// <summary>
        /// Gets or sets a selection list of available languages.
        /// </summary>
        public SelectList LanguageList { get; set; }

        /// <summary>
        /// Gets or sets a selection list of available time zones.
        /// </summary>
        public SelectList TimeZoneList { get; set; }

        /// <summary>
        /// Gets or sets a list of grants.
        /// </summary>
        public List<GrantViewModel> Grants { get; set; } = new List<GrantViewModel>();

        /// <summary>
        /// Gets or sets a value indicating whether two factor is enabled.
        /// </summary>
        public bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether passwordless authentication is enabled.
        /// </summary>
        public bool PasswordlessAuthenticationEnabled { get; set; }
    }
}