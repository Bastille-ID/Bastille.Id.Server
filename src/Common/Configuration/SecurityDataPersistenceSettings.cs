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
    public enum DataPersistenceStorageMethod
    {
        /// <summary>
        /// The default storage method is localized.
        /// </summary>
        Local,

        /// <summary>
        /// A file system path will be used instead.
        /// </summary>
        FileSystem,

        /// <summary>
        /// A Redis server will be used.
        /// </summary>
        Redis,

        /// <summary>
        /// Azure vault shall be used.
        /// </summary>
        AzureVault
    }

    /// <summary>
    /// This class contains data persistance related settings.
    /// </summary>
    public class SecurityDataPersistenceSettings
    {
        /// <summary>
        /// Gets or sets the data persistence storage method.
        /// </summary>
        public DataPersistenceStorageMethod Method { get; set; } = DataPersistenceStorageMethod.Local;

        /// <summary>
        /// Gets or sets the data persistence azure vault blob with SAS token.
        /// </summary>
        public string AzureBlobUriWithToken { get; set; }

        /// <summary>
        /// Gets or sets the data persistence folder path.
        /// </summary>
        public string FolderPath { get; set; }

        /// <summary>
        /// Gets or sets the data persistence length in days.
        /// </summary>
        public int PersistenceLengthDays { get; set; } = 90;

        /// <summary>
        /// Gets or sets the thumbprint of the certificate used to secure the data persistence.
        /// </summary>
        public string Thumbprint { get; set; }
    }
}