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
    public class PersonalDataModel : BaseModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PersonalDataModel" /> class.
        /// </summary>
        public PersonalDataModel()
        {
            this.Groups = new List<string>();
            this.Consents = new List<ConsentModel>();
        }

        /// <summary>
        /// Gets or sets the user's identity.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Gets or sets the user's email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's phone number.
        /// </summary>
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
        /// Gets or sets the user's nick name.
        /// </summary>
        public string PreferedUserName { get; set; }

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
        public DateTime? LastLoginDate { get; set; }

        /// <summary>
        /// Gets or sets the user's last login date as an xml friendly output.
        /// </summary>
        [XmlElement("LastLoginDate")]
        public string LastLoginDateString
        {
            get => this.CreationDate?.ToString("MM-dd-yyy HH:mm:ss", CultureInfo.InvariantCulture) + " UTC" ?? string.Empty;
            set => this.LastLoginDate = DateTime.Parse(value, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets or sets the user's creation date.
        /// </summary>
        [XmlIgnore]
        public DateTime? CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the user's creation date as an xml friendly output.
        /// </summary>
        [XmlElement("CreationDate")]
        public string CreationDateString
        {
            get => this.CreationDate?.ToString("MM-dd-yyy HH:mm:ss", CultureInfo.InvariantCulture) + " UTC" ?? string.Empty;
            set => this.CreationDate = DateTime.Parse(value, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets or sets the user's groups
        /// </summary>
        [XmlArrayItem("Group")]
        public List<string> Groups { get; set; }

        /// <summary>
        /// Gets or sets the user's consents,
        /// </summary>
        [XmlArrayItem("Consent")]
        public List<ConsentModel> Consents { get; set; }
    }
}