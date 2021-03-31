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
    using System.ComponentModel.DataAnnotations;
    using Bastille.Id.Core;
    using Bastille.Id.Models;
    using Bastille.Id.Server.Core.Common.Models;

    /// <summary>
    /// This class contains view model data for the tenants view.
    /// </summary>
    public class GroupsViewModel : BaseModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GroupsViewModel" /> class.
        /// </summary>
        public GroupsViewModel()
        {
            this.StatusType = StatusMessageResultType.Info;
        }

        /// <summary>
        /// Gets or sets the tenant identity.
        /// </summary>
        public Guid GroupId { get; set; }

        /// <summary>
        /// Gets or sets the tenant name.
        /// </summary>
        [Required]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the tenant address.
        /// </summary>
        public string Address { get; set; }

        /// <summary>
        /// Gets or sets the tenant contact name.
        /// </summary>
        public string ContactName { get; set; }

        /// <summary>
        /// Gets or sets the tenant contact email.
        /// </summary>
        [EmailAddress]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the tenant phone number.
        /// </summary>
        [Phone]
        public string Phone { get; set; }

        /// <summary>
        /// Gets or sets the URL to the tenant's profile picture.
        /// </summary>
        public string PictureUrl { get; set; }
    }
}