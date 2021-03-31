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
    using System.ComponentModel;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using Bastille.Id.Server.Core.Extensions;
    using IdentityServer4;
    using Talegen.Common.Core.Extensions;

    /// <summary>
    /// This enumeration represents the Response Type of the External Authentication Provider
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ResponseType
    {
        /// <summary>
        /// The authorization code response type
        /// </summary>
        [Description("code")]
        Code = 1,

        /// <summary>
        /// The access token response type
        /// </summary>
        [Description(IdentityServerConstants.TokenTypes.IdentityToken)]
        IdToken = 2
    }

    /// <summary>
    /// This class represents the External Authentication Settings Model
    /// </summary>
    public class ExternalAuthenticationSettingsModel
    {
        /// <summary>
        /// Gets or sets the external authentication setting identifier.
        /// </summary>
        /// <value>The external authentication setting identifier.</value>
        public Guid ExternalAuthenticationSettingId { get; set; }

        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        /// <value>The display name.</value>
        public string DisplayName { get; set; }

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
        /// Gets or sets the authority URL.
        /// </summary>
        /// <value>The authority URL.</value>
        public string AuthorityUrl { get; set; }

        /// <summary>
        /// Gets or sets the type of the response.
        /// </summary>
        /// <value>The type of the response.</value>
        [JsonIgnore]
        public ResponseType ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the response code.
        /// </summary>
        /// <value>The response code.</value>
        public string ResponseCode
        {
            get
            {
                return this.ResponseType.ToDescription();
            }

            set
            {
                this.ResponseType = value == ResponseType.Code.ToDescription() ? ResponseType.Code : ResponseType.IdToken;
            }
        }

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
    }
}