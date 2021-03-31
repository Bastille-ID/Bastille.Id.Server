namespace Bastille.Id.Server.Core.Security
{
    using Bastille.Id.Server.Core.Data;
    using Bastille.Id.Server.Core.Security.Models;
    using Bastille.Id.Server.Properties;
    using Microsoft.EntityFrameworkCore;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// This class represents the External Authentication Service and related business logic
    /// </summary>
    public class ExternalAuthenticationService
    {
        /// <summary>
        /// Contains an instance of the application database context.
        /// </summary>
        private readonly ApplicationDbContext context;

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalAuthenticationService" /> class.
        /// </summary>
        /// <param name="dataContext">The data context.</param>
        public ExternalAuthenticationService(ApplicationDbContext dataContext)
        {
            this.context = dataContext;
        }

        /// <summary>
        /// Finds the external authentication providers asynchronously.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Returns a List of <see cref="ExternalAuthenticationProviderModel" /> for the <see cref="ExternalAuthenticationProviderRequestModel" />.</returns>
        public async Task<List<ExternalAuthenticationProviderModel>> FindExternalAuthenticationProvidersAsync(ExternalAuthenticationProviderRequestModel request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentException(string.Format(Resources.ExternalAuthenticationMissingParameterText, nameof(request)), nameof(request));
            }

            var query = this.context.ExternalAuthenticationProviders
                .Include(provider => provider.ExternalAuthenticationSettings)
                .Include(provider => provider.ExternalAuthenticationProviderOrganizations)
                .AsNoTracking()
                .Where(externalAuth => !request.ActiveOnly || (request.ActiveOnly && externalAuth.Active == request.ActiveOnly));

            if (request.OrganizationId.HasValue)
            {
                query = query.Where(externalAuth => externalAuth.ExternalAuthenticationProviderOrganizations == null || !externalAuth.ExternalAuthenticationProviderOrganizations.Any() || (request.OrganizationId.HasValue && externalAuth.ExternalAuthenticationProviderOrganizations.Select(o => o.OrganizationId).Contains(request.OrganizationId.Value)));
            }

            if (request.AuthenticationType != null)
            {
                query = query.Where(externalAuth => request.AuthenticationType == externalAuth.AuthenticationType);
            }

            if (!string.IsNullOrWhiteSpace(request.SchemeName))
            {
                query = query.Where(externalAuth => externalAuth.SchemeName.ToLower() == request.SchemeName.ToLower());
            }

            return await query.Select(entity => entity.ToModel())
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Finds the users external authentication providers asynchronously.
        /// </summary>
        /// <param name="userName">Contains the name of the user.</param>
        /// <param name="boundOnly">Contains a boolean value used to determine if the method should return bound only providers.</param>
        /// <param name="cancellationToken">Contains the cancellation token.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException">The userName is required</exception>
        public async Task<List<ExternalAuthenticationProviderModel>> FindUsersExternalAuthenticationProvidersAsync(string userName, bool boundOnly = false, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                throw new ArgumentException(string.Format(Properties.Resources.ExternalAuthenticationMissingParameterText, nameof(userName)), nameof(userName));
            }

            List<ExternalAuthenticationProviderModel> returnModel = new List<ExternalAuthenticationProviderModel>();

            var user = await this.context.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(user => user.UserName.ToLower() == userName.ToLower(), cancellationToken)
                .ConfigureAwait(true);

            // Validate that this user exists
            if (user != null)
            {
                // Find all organizations this user has access to
                var organizationIds = await this.context.OrganizationUsers
                    .AsNoTracking()
                    .Where(ou => ou.User.UserName.ToLower() == userName.ToLower())
                    .Select(ou => ou.OrganizationId)
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);

                var boundProviderNames = await this.context.UserLogins
                    .AsNoTracking()
                    .Where(ul => ul.UserId == user.Id)
                    .Select(ul => ul.LoginProvider)
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);

                var query = await this.context.ExternalAuthenticationProviders
                    .Include(provider => provider.ExternalAuthenticationSettings)
                    .Include(provider => provider.ExternalAuthenticationProviderOrganizations)
                    .AsNoTracking()
                    .Where(externalAuth => externalAuth.Active &&
                        externalAuth.ExternalAuthenticationProviderOrganizations.Any(eap => organizationIds.Contains(eap.OrganizationId)))
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);

                returnModel = boundOnly ?
                    query.Where(eap => boundProviderNames.Any(ea => ea.ToLower() == eap.SchemeName.ToLower()))
                        .Select(entity => entity.ToModel()).ToList() :
                    query.Select(entity => entity.ToModel()).ToList();
            }

            return returnModel;
        }

        /// <summary>
        /// Finds the domain white list asynchronous.
        /// </summary>
        /// <param name="domainName">Name of the domain.</param>
        /// <returns>Returns a <see cref="DomainWhiteList" /> object matching the requested domain name.</returns>
        /// <exception cref="ArgumentException"><see cref="Properties.Resources.InvalidDomainWhiteListNameErrorText" /></exception>
        public async Task<DomainWhiteList> FindDomainWhiteListAsync(string domainName)
        {
            if (string.IsNullOrWhiteSpace(domainName))
            {
                throw new ArgumentException(Properties.Resources.InvalidDomainWhiteListNameErrorText);
            }

            // Store the domain name as Upper so it's not being done on every pass of the query below
            string upperDomainName = domainName
                .ToUpperInvariant();

            // Get just the domain name to perform wildcard search
            string wildCardDomainName = upperDomainName.IndexOf('.') > 0 ?
                upperDomainName.Substring(upperDomainName.IndexOf('.') + 1, upperDomainName.Length - (upperDomainName.IndexOf('.') + 1)) :
                upperDomainName;

            // Get a list of the active domain whitelists
            List<DomainWhiteList> domainWhiteLists = await this.context.DomainWhiteLists
                .AsNoTracking()
                .Where(dwl => dwl.Active)
                .ToListAsync()
                .ConfigureAwait(false);

            // Return the matching domain whitelist
            return domainWhiteLists.FirstOrDefault(
                dwl => dwl.DomainName.ToUpperInvariant() == upperDomainName ||
                (dwl.DomainName.StartsWith('*') && dwl.DomainName.Replace("*.", "", true, CultureInfo.InvariantCulture).ToUpperInvariant().EndsWith(wildCardDomainName, true, CultureInfo.InvariantCulture)));
        }

        /// <summary>
        /// Finds the active domain white lists asynchronous.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Returns a List of <see cref="DomainWhiteList" /> objects where Active is true.</returns>
        public async Task<List<DomainWhiteList>> FindActiveDomainWhiteListsAsync(CancellationToken cancellationToken)
        {
            return await this.context.DomainWhiteLists
                .Where(dwl => dwl.Active)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }
}