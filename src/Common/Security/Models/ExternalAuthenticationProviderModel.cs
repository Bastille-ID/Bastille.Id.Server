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
    using Bastille.Id.Models.Security;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Contains an enumerated list of persistence storage methods.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ExternalAuthenticationType
    {
        /// <summary>
        /// A Google Authentication Type
        /// </summary>
        Google,

        /// <summary>
        /// Facebook
        /// </summary>
        Facebook,

        /// <summary>
        /// Twitter
        /// </summary>
        Twitter,

        /// <summary>
        /// Microsoft
        /// </summary>
        Microsoft,

        /// <summary>
        /// An Open Id Connect Authentication Type
        /// </summary>
        OpenIdConnect,

        /// <summary>
        /// Okta
        /// </summary>
        Okta
    }

    /// <summary>
    /// This entity class represents the external application model within the identity data store.
    /// </summary>
    public class ExternalAuthenticationProviderModel : ExternalProviderModel
    {
        /// <summary>
        /// Gets or sets the external authentication provider identifier.
        /// </summary>
        /// <value>The external authentication provider identifier.</value>
        public Guid ExternalAuthenticationProviderId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Gets or sets the type of the authentication.
        /// </summary>
        public ExternalAuthenticationType AuthenticationType { get; set; } = ExternalAuthenticationType.OpenIdConnect;

        /// <summary>
        /// Gets or sets the settings.
        /// </summary>
        public ExternalAuthenticationSettingsModel Settings { get; set; } = new ExternalAuthenticationSettingsModel();

        /// <summary>
        /// Gets or sets a value indicating whether the External Authentication Provider is active.
        /// </summary>
        public bool Active { get; set; }
    }
}