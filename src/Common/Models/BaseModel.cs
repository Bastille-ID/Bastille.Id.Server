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

namespace Bastille.Id.Server.Core.Common.Models
{
    using System.Xml.Serialization;
    using Bastille.Id.Core;
    using Bastille.Id.Models;

    /// <summary>
    /// This class is the base model that hosts some base props.
    /// </summary>
    public abstract class BaseModel
    {
        /// <summary>
        /// Gets or sets the response status message.
        /// </summary>
        [XmlIgnore]
        public string StatusMessage { get; set; }

        /// <summary>
        /// Gets or sets the response status message type.
        /// </summary>
        [XmlIgnore]
        public StatusMessageResultType StatusType { get; set; } = StatusMessageResultType.None;
    }
}