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

namespace Bastille.Id.Server.Core.Settings
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Contains an enumerated list of persistence storage methods.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum DataPersistanceStorageMethod
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
    public class DataPersistanceSettings
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DataPersistanceSettings" /> class.
        /// </summary>
        public DataPersistanceSettings()
        {
            this.DataPersistanceStorageMethod = DataPersistanceStorageMethod.Local;
            this.DataPersistanceLengthDays = 90;
        }

        /// <summary>
        /// Gets or sets the data persistence storage method.
        /// </summary>
        public DataPersistanceStorageMethod DataPersistanceStorageMethod { get; set; }

        /// <summary>
        /// Gets or sets the data persistence azure vault blob with SAS token.
        /// </summary>
        public string DataPersistenceAzureBlobUriWithToken { get; set; }

        /// <summary>
        /// Gets or sets the data persistence folder path.
        /// </summary>
        public string DataPersistanceFolderPath { get; set; }

        /// <summary>
        /// Gets or sets the data persistence length in days.
        /// </summary>
        public int DataPersistanceLengthDays { get; set; }

        /// <summary>
        /// Gets or sets the thumbprint of the certificate used to secure the data persistence.
        /// </summary>
        public string DataPersistanceThumbprint { get; set; }
    }
}