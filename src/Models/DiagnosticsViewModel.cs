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

namespace Bastille.Id.Server.Models
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using IdentityModel;
    using Microsoft.AspNetCore.Authentication;
    using Newtonsoft.Json;

    /// <summary>
    /// This class is the diagnostics page view model.
    /// </summary>
    public class DiagnosticsViewModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DiagnosticsViewModel" /> class.
        /// </summary>
        /// <param name="result">Contains an <see cref="AuthenticateResult" /> object.</param>
        public DiagnosticsViewModel(AuthenticateResult result)
        {
            this.AuthenticateResult = result ?? throw new ArgumentNullException(nameof(result));

            if (result.Properties.Items.ContainsKey("client_list"))
            {
                string encoded = result.Properties.Items["client_list"];
                byte[] bytes = Base64Url.Decode(encoded);
                string value = Encoding.UTF8.GetString(bytes);
                this.Clients = new List<string>(JsonConvert.DeserializeObject<string[]>(value));
            }
        }

        /// <summary>
        /// Gets the authentication result.
        /// </summary>
        public AuthenticateResult AuthenticateResult { get; }

        /// <summary>
        /// Gets an enumerable list of clients.
        /// </summary>
        public List<string> Clients { get; } = new List<string>();
    }
}