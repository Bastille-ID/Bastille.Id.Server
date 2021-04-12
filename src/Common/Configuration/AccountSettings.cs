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
    using System;
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Contains an enumerated list of required authentication identifier types.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum LoginIdentifierMethod
    {
        /// <summary>
        /// User must specify their user name.
        /// </summary>
        UserName,

        /// <summary>
        /// User must specify their e-mail address.
        /// </summary>
        Email,

        /// <summary>
        /// User can specify their username, or email address
        /// </summary>
        UserNameOrEmail,

        /// <summary>
        /// User can specify their username, email address, or phone number
        /// </summary>
        UserNameOrEmailOrPhone
    }

    /// <summary>
    /// This class contains all identity server account related settings pulled from application config.
    /// </summary>
    public class AccountSettings
    {
        /// <summary>
        /// Gets or sets a value indicating whether [allow registration].
        /// </summary>
        /// <value><c>true</c> if [allow registration]; otherwise, <c>false</c>.</value>
        public bool AllowRegistration { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether local login is provided.
        /// </summary>
        public bool AllowLocalLogin { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the option to remember a login is provided.
        /// </summary>
        public bool AllowRememberLogin { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the user email address must be unique. Default is true.
        /// </summary>
        public bool RequireUniqueEmail { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether e-mail verification is required for new users.
        /// </summary>
        public bool RequiresEmailVerification { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether phone verification is required for new users.
        /// </summary>
        public bool RequiresPhoneVerification { get; set; }

        /// <summary>
        /// Gets or sets the remember me login duration.
        /// </summary>
        public int RememberMeLoginDurationDays { get; set; } = 30;

        /// <summary>
        /// Gets or sets a value indicating whether the user is prompted to log out.
        /// </summary>
        public bool ShowLogoutPrompt { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the user is redirected after signing out.
        /// </summary>
        public bool AutomaticRedirectAfterSignOut { get; set; } = false;

        /// <summary>
        /// Gets or sets the Windows authentication scheme being used
        /// </summary>
        public string WindowsAuthenticationSchemeName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether if a user uses windows authentication, should we load the groups from windows.
        /// </summary>
        public bool IncludeWindowsGroups { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user must specify a first and last name during registration.
        /// </summary>
        public bool RequireNameIdentification { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user can sign-in before their e-mail has been verified.
        /// </summary>
        public bool AllowSignInBeforeEmailVerification { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user account has limited access when AllowSignInBeforeEmailVerification is true but the user has not
        /// verified their account.
        /// </summary>
        public bool LimitAccessBeforeEmailVerification { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether [allow external automatic provision].
        /// </summary>
        /// <value><c>true</c> if [allow external automatic provision]; otherwise, <c>false</c>.</value>
        public bool AllowExternalAutoProvision { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether [allow external registration].
        /// </summary>
        /// <value><c>true</c> if [allow external registration]; otherwise, <c>false</c>.</value>
        public bool AllowExternalRegistration { get; set; } = true;

        /// <summary>
        /// Gets or sets the terms URL.
        /// </summary>
        /// <value>The terms URL.</value>
        public Uri TermsUrl { get; set; }

        /// <summary>
        /// Gets or sets the required identifier method.
        /// </summary>
        public LoginIdentifierMethod RequiredLoginIdentifier { get; set; } = LoginIdentifierMethod.UserNameOrEmail;

        /// <summary>
        /// Gets or sets the two factor settings
        /// </summary>
        public TwoFactorSettings TwoFactor { get; set; } = new TwoFactorSettings();

        /// <summary>
        /// Gets or sets account password settings
        /// </summary>
        public AccountPasswordSettings Passwords { get; set; } = new AccountPasswordSettings();

        /// <summary>
        /// Gets or sets the external providers.
        /// </summary>
        /// <value>The external providers.</value>
        public List<ExternalProviderSettings> ExternalProviders { get; set; } = new List<ExternalProviderSettings>();
    }
}