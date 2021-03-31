﻿/*
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
    using System.ComponentModel.DataAnnotations;
    using Bastille.Id.Server.Properties;

    /// <summary>
    /// This class defines a two-factor input view model
    /// </summary>
    public class TwoFactorInputModel
    {
        /// <summary>
        /// Gets or sets the two factor code.
        /// </summary>
        [Required]
        [StringLength(7, ErrorMessageResourceName = ResourceKeys.StringLengthRequirementsText, ErrorMessageResourceType = typeof(Resources), MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = ResourceKeys.TwoFactorAuthenticationCodeText, ResourceType = typeof(Resources))]
        public string Code { get; set; }
    }
}