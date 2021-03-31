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

namespace Bastille.Id.Server.Core.Identity
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using IdentityServer4.Models;
    using IdentityServer4.Validation;

    /// <summary>
    /// <para>
    /// This class implements the Identity Server grant extension for the custom delegation grant type. The custom delegation grant type will allow a token from
    /// a SPA client to be reissued by an API resource to access another API in the context of the given SPA client subject. This allows the SPA client to be
    /// limited in scope to the first API (usually Inspire API and let the Inspire API access a secondary API delegating the user's id with that communication
    /// on the back channel.
    /// </para>
    /// <para>
    /// This is important for interactive clients like the custom editor Orchid that retrieves the user's identity with it's authentication and then needs to
    /// pass that user identity on to a back channel communication with a specific Inspire API request.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Additionally you need to make a request for a new delegation token using the following request: POST /connect/token grant_type=delegation scope=api2
    /// token=... client_id=api1.client client_secret=secret
    /// </remarks>
    public class DelegationGrantValidator : IExtensionGrantValidator
    {
        #region Private Fields

        /// <summary>
        /// Contains the token validator
        /// </summary>
        private readonly ITokenValidator validator;

        #endregion Private Fields

        #region Public Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="DelegationGrantValidator" /> class.
        /// </summary>
        /// <param name="validator">Contains the validator.</param>
        public DelegationGrantValidator(ITokenValidator validator)
        {
            this.validator = validator;
        }

        #endregion Public Constructors

        #region Public Properties

        /// <summary>
        /// Returns the grant type this validator can deal with
        /// </summary>
        /// <value>The type of the grant.</value>
        public string GrantType => CustomGrants.DelegationGrant;

        #endregion Public Properties

        #region Public Methods

        /// <summary>
        /// Validates the custom grant request.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>Contains the task object.</returns>
        public Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return this.ProcessValidateAsync(context);
        }

        #endregion Public Methods

        #region Private Methods

        /// <summary>
        /// Processes the validate asynchronous.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>Contains the task object.</returns>
        private async Task ProcessValidateAsync(ExtensionGrantValidationContext context)
        {
            // get the token from the raw request parameter
            var userToken = context.Request.Raw.Get("token");

            // if no token was specified...
            if (!string.IsNullOrEmpty(userToken))
            {
                // validate the access token
                TokenValidationResult result = await this.validator.ValidateAccessTokenAsync(userToken);

                // if the validation was successful...
                if (!result.IsError)
                {
                    // get user's identity (subject id) and build the result for context.
                    string subjectId = result.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? string.Empty;
                    context.Result = new GrantValidationResult(subjectId, this.GrantType);
                }
                else
                {
                    context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, result.Error);
                }
            }
            else
            {
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, Properties.Resources.InvalidGrantMissingTokenParameterErrorText);
            }
        }

        #endregion Private Methods
    }
}