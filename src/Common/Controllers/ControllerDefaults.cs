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

namespace Bastille.Id.Server.Core.Common
{
    /// <summary>
    /// This class contains controller constants for the application interface.
    /// </summary>
    public static class ControllerDefaults
    {
        /// <summary>
        /// The base redirect URL
        /// </summary>
        public const string BaseRedirectUrl = "~/";

        /// <summary>
        /// The account controller name.
        /// </summary>
        public const string AccountControllerName = "Account";

        /// <summary>
        /// The external controller name.
        /// </summary>
        public const string ExternalControllerName = "External";

        /// <summary>
        /// The logged out view name.
        /// </summary>
        public const string LoggedOutViewName = "LoggedOut";

        /// <summary>
        /// The return URL parameter.
        /// </summary>
        public const string ReturnUrlParameter = "returnUrl";

        /// <summary>
        /// The scheme parameter.
        /// </summary>
        public const string SchemeParameter = "scheme";

        /// <summary>
        /// The default logo image name.
        /// </summary>
        public const string DefaultLogoImageName = "/img/logo.png";

        /// <summary>
        /// Contains the two-factor authentication uri format string.
        /// </summary>
        public const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        /// <summary>
        /// The default terms URL.
        /// </summary>
        public const string DefaultTermsUrl = "https://talegen.com/terms";
    }
}