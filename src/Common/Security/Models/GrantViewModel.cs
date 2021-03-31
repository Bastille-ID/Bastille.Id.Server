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

    /// <summary>
    /// This class is the grant page view model.
    /// </summary>
    public class GrantViewModel
    {
        /// <summary>
        /// Gets or sets the client identity.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client name.
        /// </summary>
        public string ClientName { get; set; }

        /// <summary>
        /// Gets or sets the client URL.
        /// </summary>
        public string ClientUrl { get; set; }

        /// <summary>
        /// Gets or sets the client Logo URL.
        /// </summary>
        public string ClientLogoUrl { get; set; }

        /// <summary>
        /// Gets or sets the date the grant was created.
        /// </summary>
        public DateTime Created { get; set; }

        /// <summary>
        /// Gets or sets the date when the grant expires.
        /// </summary>
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of identity grants.
        /// </summary>
        public IEnumerable<string> IdentityGrantNames { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of API grants.
        /// </summary>
        public IEnumerable<string> ApiGrantNames { get; set; }
    }
}