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
    /// <summary>
    /// This class contains account password settings options.
    /// </summary>
    public class AccountPasswordSettings
    {
        /// <summary>
        /// Gets or sets the minimum length a password must be. Defaults to 8.
        /// </summary>
        public int RequiredLength { get; set; } = 8;

        /// <summary>
        /// Gets or sets the minimum number of unique chars a password must comprised of. Defaults to 1.
        /// </summary>
        public int RequiredUniqueChars { get; set; } = 1;

        /// <summary>
        /// Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. Defaults to true.
        /// </summary>
        public bool RequireNonAlphanumeric { get; set; } = true;

        /// <summary>
        /// Gets or sets a flag indicating if passwords must contain a lower case ASCII character. Defaults to true.
        /// </summary>
        public bool RequireLowercase { get; set; } = true;

        /// <summary>
        /// Gets or sets a flag indicating if passwords must contain a upper case ASCII character. Defaults to true.
        /// </summary>
        public bool RequireUppercase { get; set; } = true;

        /// <summary>
        /// Gets or sets a flag indicating if passwords must contain a digit. Defaults to true.
        /// </summary>
        public bool RequireDigit { get; set; } = true;
    }
}