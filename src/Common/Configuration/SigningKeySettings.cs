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

namespace Bastille.Id.Server.Core.Configuration
{
    using System.Security.Cryptography.X509Certificates;
    using System.Text.Json.Serialization;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// This class contains signing key settings.
    /// </summary>
    public class SigningKeySettings
    {
        /// <summary>
        /// Gets or sets a value indicating whether the application is running in the Azure environment.
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;

        /// <summary>
        /// Gets or sets the configuration key in store.
        /// </summary>
        public string Thumbprint { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [generate self signing].
        /// </summary>
        /// <value><c>true</c> if [generate self signing]; otherwise, <c>false</c>.</value>
        public bool GenerateSelfSigning { get; set; }
    }
}