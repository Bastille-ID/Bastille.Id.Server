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
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Contains an enumerated list of persistence storage methods.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ExternalAuthenticationProviders
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
        /// An Open Id Connect Authentication Type like Bastille, Okta, Auth0, or other OIDC compliant provider.
        /// </summary>
        OpenIdConnect
    }

    /// <summary>
    /// This class represents external provider settings.
    /// </summary>
    public class ExternalProviderSettings
    {
        /// <summary>
        /// Gets or sets the provider.
        /// </summary>
        /// <value>The provider.</value>
        public ExternalAuthenticationProviders Provider { get; set; } = ExternalAuthenticationProviders.OpenIdConnect;

        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        /// <value>The display name. If empty, the Provider enumeration description shall be used.</value>
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the authority.
        /// </summary>
        /// <value>The authority.</value>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets the name of the scheme.
        /// </summary>
        /// <value>The name of the scheme.</value>
        public string SchemeName { get; set; }

        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        /// <value>The client identifier.</value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        /// <value>The client secret.</value>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the type of the response.
        /// </summary>
        /// <value>The type of the response.</value>
        public string ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the callback path.
        /// </summary>
        /// <value>The callback path.</value>
        public string CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the signed out callback path.
        /// </summary>
        /// <value>The signed out callback path.</value>
        public string SignedOutCallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the remote sign out path.
        /// </summary>
        /// <value>The remote sign out path.</value>
        public string RemoteSignOutPath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [validate issuer].
        /// </summary>
        /// <value><c>true</c> if [validate issuer]; otherwise, <c>false</c>.</value>
        public bool ValidateIssuer { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether [get claims from user information endpoint].
        /// </summary>
        /// <value><c>true</c> if [get claims from user information endpoint]; otherwise, <c>false</c>.</value>
        public bool GetClaimsFromUserInfoEndpoint { get; set; } = true;
    }
}