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

namespace Bastille.Id.Server.Core.Reports.Models
{
    using System;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Models.Logging;

    /// <summary>
    /// This model contains properties for the display of recent logins on the dashboard.
    /// </summary>
    public class DashboardRecentLoginsModel
    {
        /// <summary>
        /// Gets or sets the event-date time.
        /// </summary>
        public DateTime EventDateTime { get; set; }

        /// <summary>
        /// Gets or sets the client address.
        /// </summary>
        public string ClientAddress { get; set; }

        /// <summary>
        /// Gets or sets the user identity.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Gets or sets the email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the event result.
        /// </summary>
        public AuditResult Result { get; set; }
    }
}