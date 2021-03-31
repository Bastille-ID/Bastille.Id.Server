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
    using System.Reflection;
    using Bastille.Id.Core.Configuration;
    using Newtonsoft.Json;
    using Talegen.AspNetCore.hCAPTCHA;
    using Talegen.AspNetCore.Web.Configuration;
    using Talegen.Common.Messaging.Configuration;

    /// <summary>
    /// This class contains application settings for the identity server.
    /// </summary>
    public class ApplicationSettings
    {
        #region Private Fields

        /// <summary>
        /// Contains the application version.
        /// </summary>
        private string version;

        /// <summary>
        /// Contains the application copyright.
        /// </summary>
        private string copyright;

        #endregion

        /// <summary>
        /// Gets the application version.
        /// </summary>
        [JsonIgnore]
        public string Version
        {
            get
            {
                if (string.IsNullOrEmpty(this.version))
                {
                    this.version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                }

                return this.version;
            }
        }

        /// <summary>
        /// Gets the application copyright.
        /// </summary>
        [JsonIgnore]
        public string Copyright
        {
            get
            {
                if (string.IsNullOrEmpty(this.copyright))
                {
                    this.copyright = ((AssemblyCopyrightAttribute)Assembly.GetExecutingAssembly().GetCustomAttribute(typeof(AssemblyCopyrightAttribute))).Copyright;
                }

                return this.copyright;
            }
        }

        /// <summary>
        /// Gets or sets the security settings.
        /// </summary>
        /// <value>The security settings.</value>
        public SecuritySettings Security { get; set; }

        /// <summary>
        /// Gets or sets the webhook settings.
        /// </summary>
        public WebhookSettings Webhook { get; set; }

        /// <summary>
        /// Gets or sets an instance of the <see cref="MessagingSettings" /> class.
        /// </summary>
        public MessagingSettings Messaging { get; set; }

        /// <summary>
        /// Gets or sets an instance of the <see cref="AccountSettings" /> class.
        /// </summary>
        public AccountSettings Account { get; set; }

        /// <summary>
        /// Gets or sets the storage.
        /// </summary>
        /// <value>The storage.</value>
        public StorageSettings Storage { get; set; }

        /// <summary>
        /// Gets or sets an instance of the <see cref="ApplicationInsightSettings" /> class.
        /// </summary>
        public ApplicationInsightSettings ApplicationInsights { get; set; }

        /// <summary>
        /// Gets or sets the advanced settings.
        /// </summary>
        /// <value>The advanced settings.</value>
        public AdvancedSettings Advanced { get; set; }

        /// <summary>
        /// Gets or sets the CAPTCHA settings.
        /// </summary>
        /// <value>The captcha settings.</value>
        public CaptchaOptions Captcha { get; set; } = new CaptchaOptions();
    }
}