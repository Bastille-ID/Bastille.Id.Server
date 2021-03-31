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

namespace Bastille.Id.Server.Common.Identity
{
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core.Data;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Core.Security;
    using IdentityServer4.Services;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Caching.Distributed;
    using Talegen.Common.Core.Extensions;
    using Vasont.AspnetCore.RedisClient;

    /// <summary>
    /// This class contains extension methods for Identity Server interactions.
    /// </summary>
    public static class InteractionExtensions
    {
        /// <summary>
        /// Finds the tenant configuration.
        /// </summary>
        /// <returns>Returns a <see cref="TenantConfig" /> object if found.</returns>
        public static async Task<TenantConfig> FindTenantConfigAsync(this IIdentityServerInteractionService interaction, ApplicationDbContext dataContext, IAdvancedDistributedCache cache, string returnUrl, CancellationToken cancellationToken = default)
        {
            var authRequest = await interaction.GetAuthorizationContextAsync(returnUrl);
            TenantConfig tenantConfig = null;

            if (authRequest != null)
            {
                // see if there is an ACR of tenant:name_of_tenant
                string tenantKey = authRequest.Tenant;
                if (!string.IsNullOrWhiteSpace(tenantKey))
                {
                    // return the value after tenant: prefix
                    tenantKey = tenantKey.After(':');
                }

                // if we found the domain key out of the acr values...
                if (!string.IsNullOrWhiteSpace(tenantKey))
                {
                    tenantConfig = await TenantHelpers.FindTenantByKeyAsync(tenantKey, cache, dataContext, cancellationToken);
                }
            }

            return tenantConfig;
        }
    }
}