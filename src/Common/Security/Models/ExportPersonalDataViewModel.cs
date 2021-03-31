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
    /// <summary>
    /// This class is the export personal data view model.
    /// </summary>
    public class ExportPersonalDataViewModel
    {
        /// <summary>
        /// Gets or sets a value indicating whether organization information should be exported.
        /// </summary>
        public bool IncludeGroups { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether consent information should be exported.
        /// </summary>
        public bool IncludeGrants { get; set; }
    }
}