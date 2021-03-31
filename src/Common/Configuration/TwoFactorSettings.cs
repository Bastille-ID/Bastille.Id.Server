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
    /// Contains an enumerated list of two-factor authentication methods.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum TwoFactorMethod
    {
        /// <summary>
        /// No two factor enabled
        /// </summary>
        None,

        /// <summary>
        /// E-mail Service enabled.
        /// </summary>
        Email,

        /// <summary>
        /// SMS service enabled.
        /// </summary>
        SMS,

        /// <summary>
        /// Timed One-time Password enabled.
        /// </summary>
        TOTP
    }

    /// <summary>
    /// This class contains the settings for two-factor authentication
    /// </summary>
    public class TwoFactorSettings
    {
        /// <summary>
        /// Gets or sets the two-factor authentication method.
        /// </summary>
        public TwoFactorMethod Method { get; set; } = TwoFactorMethod.None;
    }
}