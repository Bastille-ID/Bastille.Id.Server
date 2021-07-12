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
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Xml.Serialization;
    using Bastille.Id.Models.Clients.Consent;
    using Bastille.Id.Models.Security;
    using Bastille.Id.Server.Core.Common.Models;

    /// <summary>
    /// This class is the exporting personal data model.
    /// </summary>
    [Serializable]
    public class ExportPersonalDataModel : BaseModel
    {
        /// <summary>
        /// Gets or sets the user's identity.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Gets or sets the user's email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's normalized email.
        /// </summary>
        public string NormalizedEmail { get; set; }

        /// <summary>
        /// Gets or sets the user's normalized user name.
        /// </summary>
        public string NormalizedUserName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user is able to be locked out.
        /// </summary>
        public bool LockoutEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether two factor authentication is enabled.
        /// </summary>
        public bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// Gets or sets the user's phone number.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the user's mobile number.
        /// </summary>
        public string MobilePhone { get; set; }

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
        /// Gets or sets the user's nick name.
        /// </summary>
        public string PreferredUserName { get; set; }

        /// <summary>
        /// Gets or sets the web site.
        /// </summary>
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
        /// Gets or sets the user's last login date.
        /// </summary>
        [XmlIgnore]
        public DateTime LastLoginDate { get; set; }

        /// <summary>
        /// Gets or sets the user's last login date as an xml friendly output.
        /// </summary>
        [XmlElement(nameof(LastLoginDate))]
        public string LastLoginDateString
        {
            get => this.CreationDate.ToString("MM-dd-yyy HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            set => this.LastLoginDate = DateTime.Parse(value, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets or sets the user's creation date.
        /// </summary>
        [XmlIgnore]
        public DateTime CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the user's creation date as an xml friendly output.
        /// </summary>
        [XmlElement(nameof(CreationDate))]
        public string CreationDateString
        {
            get => this.CreationDate.ToString("MM-dd-yyy HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            set => this.CreationDate = DateTime.Parse(value, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets or sets the user's organization name,
        /// </summary>
        [XmlArrayItem("Group")]
        public List<GroupsViewModel> Groups { get; set; } = new List<GroupsViewModel>();

        /// <summary>
        /// Gets or sets the user's consents,
        /// </summary>
        [XmlArrayItem("Consent")]
        public List<ConsentModel> Consents { get; set; } = new List<ConsentModel>();
    }
}