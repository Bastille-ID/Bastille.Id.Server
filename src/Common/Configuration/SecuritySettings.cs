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
    using System.Collections.Generic;

    /// <summary>
    /// This class contains security related settings.
    /// </summary>
    public class SecuritySettings
    {
        /// <summary>
        /// Gets or sets the data persistence settings.
        /// </summary>
        public SecurityDataPersistenceSettings DataPersistence { get; set; } = new SecurityDataPersistenceSettings();

        /// <summary>
        /// Gets or sets the signing key.
        /// </summary>
        /// <value>The signing key.</value>
        public SigningKeySettings SigningKey { get; set; } = new SigningKeySettings();

        /// <summary>
        /// Gets or sets the allowed origins.
        /// </summary>
        /// <value>The allowed origins.</value>
        public List<string> AllowedOrigins { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the application key. The application key is used for sensitive information protection. It is base64 encoded.
        /// </summary>
        /// <value>The application key.</value>
        public string AppKey { get; set; }
    }
}