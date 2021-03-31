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
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Linq;
    using Bastille.Id.Models.Security;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Contains an enumerated list of login steps.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum LoginStep
    {
        /// <summary>
        /// Cancel
        /// </summary>
        Cancel,

        /// <summary>
        /// Confirm user name
        /// </summary>
        UserName,

        /// <summary>
        /// Confirm password
        /// </summary>
        Password
    }

    /// <summary>
    /// This class is the login input model.
    /// </summary>
    public class LoginInputModel : IExternalProviderModel
    {
        /// <summary>
        /// Gets or sets the step.
        /// </summary>
        /// <value>The step.</value>
        public LoginStep Step { get; set; } = LoginStep.UserName;

        /// <summary>
        /// Gets or sets the user name.
        /// </summary>
        [Required]
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        [Required]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to remember login.
        /// </summary>
        public bool RememberLogin { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether local login is enabled.
        /// </summary>
        public bool EnableLocalLogin { get; set; }

        /// <summary>
        /// Gets or sets the return URL.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of <see cref="ExternalProviderModel" /> objects.
        /// </summary>
        public IEnumerable<ExternalProviderModel> ExternalProviders { get; set; }

        /// <summary>
        /// Gets or sets an enumerable list of visible <see cref="ExternalProviderModel" /> objects.
        /// </summary>
        public IEnumerable<ExternalProviderModel> VisibleExternalProviders => this.ExternalProviders?.Where(x => !string.IsNullOrWhiteSpace(x.DisplayName)) ?? new List<ExternalProviderModel>();

        /// <summary>
        /// Gets a value indicating whether external login only.
        /// </summary>
        public bool IsExternalLoginOnly => !this.EnableLocalLogin && this.ExternalProviders?.Count() == 1;

        /// <summary>
        /// Gets a value indicating the external login scheme if external only.
        /// </summary>
        public string ExternalLoginScheme => this.IsExternalLoginOnly ? this.ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
    }
}