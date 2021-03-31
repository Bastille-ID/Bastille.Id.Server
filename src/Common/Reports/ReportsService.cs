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

namespace Bastille.Id.Server.Core.Reports
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Core;
    using Bastille.Id.Models.Analytics;
    using Bastille.Id.Models.Logging;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Reports.Models;
    using IdentityModel;
    using IdentityServer4.EntityFramework.Entities;
    using Microsoft.EntityFrameworkCore;

    /// <summary>
    /// This class contains methods for querying the application database for report related data and queries.
    /// </summary>
    public class ReportsService
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReportsService" /> class.
        /// </summary>
        /// <param name="serverContext">Contains an instance of the current application context.</param>
        public ReportsService(ApplicationContext<ApplicationSettings> serverContext)
        {
            this.Context = serverContext;
        }

        /// <summary>
        /// Gets the <see cref="ApplicationContext{ApplicationSettings}" /> used for report database queries.
        /// </summary>
        public ApplicationContext<ApplicationSettings> Context { get; }

        /// <summary>
        /// This method is used to retrieve latest login events from the server.
        /// </summary>
        /// <param name="groupId">Contains the group identity if specified.</param>
        /// <param name="lastWeek">Contains the last week date time.</param>
        /// <param name="pageSize">Contains the result page size.</param>
        /// <param name="cancellationToken">Contains an optional cancellation token.</param>
        /// <returns>Returns a list of <see cref="DashboardRecentLoginsModel" /> objects.</returns>
        public async Task<List<DashboardRecentLoginsModel>> RecentLoginEventsAsync(Guid groupId, DateTime lastWeek, int pageSize = 10, CancellationToken cancellationToken = default)
        {
            List<DashboardRecentLoginsModel> recentLoginEvents = null;

            if (groupId != Guid.Empty)
            {
                // have to break up query to solve EF bug/error.
                var queryResults = await this.Context.DataContext.AuditLogs
                    .Include(sl => sl.User)
                    .AsNoTracking()
                    .Join(this.Context.DataContext.GroupUsers,
                        ou => ou.UserId, sl => sl.UserId,
                        (sl, ou) => new { groupUser = ou, SecurityLog = sl })
                    .Where(sl => sl.SecurityLog.EventDateTime >= lastWeek
                        && sl.SecurityLog.Event == AuditEvent.Login
                        && sl.SecurityLog.User != null && sl.groupUser != null
                        && sl.groupUser.GroupId == groupId)
                    .OrderByDescending(sl => sl.SecurityLog.EventDateTime)
                    .Take(pageSize)
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);

                // loop through query results and build logins models.
                recentLoginEvents = queryResults.Select(log => new DashboardRecentLoginsModel
                {
                    Result = log.SecurityLog.Result,
                    EventDateTime = log.SecurityLog.EventDateTime,
                    ClientAddress = log.SecurityLog.ClientAddress,
                    UserId = log.SecurityLog.User != null ? log.SecurityLog.User.Id : Guid.Empty,
                    Email = log.SecurityLog.User != null ? log.SecurityLog.User.Email : string.Empty,
                    Name = log.SecurityLog.User == null ? string.Empty :
                            (this.Context.DataContext.UserClaims.Where(uc => uc.UserId == log.SecurityLog.User.Id && uc.ClaimType == JwtClaimTypes.GivenName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty) + " " +
                            (this.Context.DataContext.UserClaims.Where(uc => uc.UserId == log.SecurityLog.User.Id && uc.ClaimType == JwtClaimTypes.FamilyName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty)
                }).ToList();
            }
            else
            {
                recentLoginEvents = await this.Context.DataContext.AuditLogs
                .AsNoTracking()
                .Where(sl => sl.EventDateTime >= lastWeek && sl.Event == AuditEvent.Login)
                .OrderByDescending(sl => sl.EventDateTime)
                .Take(pageSize)
                .Select(log => new DashboardRecentLoginsModel
                {
                    Result = log.Result,
                    EventDateTime = log.EventDateTime,
                    ClientAddress = log.ClientAddress,
                    UserId = log.User != null ? log.User.Id : Guid.Empty,
                    Email = log.User != null ? log.User.Email : string.Empty,
                    Name = log.User == null ? string.Empty :
                        (this.Context.DataContext.UserClaims.Where(uc => uc.UserId == log.User.Id && uc.ClaimType == JwtClaimTypes.GivenName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty) + " " +
                        (this.Context.DataContext.UserClaims.Where(uc => uc.UserId == log.User.Id && uc.ClaimType == JwtClaimTypes.FamilyName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty)
                })
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            }

            return recentLoginEvents;
        }

        /// <summary>
        /// This method is used to query the security log and return log information
        /// </summary>
        /// <param name="groupId">Contains optional tenant identity used to filter results from all the users of that group.</param>
        /// <param name="userId">Contains optional user identity used to filter results for that specific user.</param>
        /// <param name="historyDays">Contains the number of days of history to return. Maximum is 90 days.</param>
        /// <param name="cancellationToken">Contains an optional cancellation token.</param>
        /// <returns>Returns a list of <see cref="LoginReportResult" /> entity objects if found.</returns>
        public async Task<List<LoginReportResult>> LoginReportAsync(Guid groupId, Guid userId = default, int historyDays = 7, CancellationToken cancellationToken = default)
        {
            if (historyDays > 90)
            {
                historyDays = 90;
            }
            else if (historyDays < 1)
            {
                historyDays = 7;
            }

            throw new NotImplementedException();
            ////string query =
            ////    "SELECT CONVERT(char(10), RF.[EventDateTime], 121) AS [Timestamp], COUNT(1) AS row_counts, SUM(SuccessCount) as SuccessCount, SUM(FailCount) AS FailCount" +
            ////    " FROM (SELECT *, CASE WHEN[Result] = 'Success' THEN 1 ELSE 0 END AS SuccessCount, CASE WHEN[Result] = 'Fail' THEN 1 ELSE 0 END AS FailCount" +
            ////    " FROM AuditLogs" +
            ////    " WHERE [Event] = 'Login') RF" +
            ////    " LEFT JOIN GroupUsers OU ON OU.GroupId = @groupId AND RF.UserId IN (OU.UserId)" +
            ////    " WHERE [EventDateTime] >= DATEADD(day, -@historyDays, GETUTCDATE())";

            ////// check for matching userId only if an organizationId was not passed-in, it cannot be both
            ////if (groupId == Guid.Empty && userId != Guid.Empty)
            ////{
            ////    query += " AND RF.UserId = @userId";
            ////}

            ////query += " GROUP BY CONVERT(char(10), RF.[EventDateTime], 121) ORDER BY[timestamp] ASC";

            ////// execute and return the results
            ////return await this.Context.DataContext.SqlQueryAsync<LoginReportResult>(query, cancellationToken,
            ////    new SqlParameter("@groupId", groupId),
            ////    new SqlParameter("@historyDays", historyDays),
            ////    new SqlParameter("@userId", userId)).ConfigureAwait(false);
        }

        /// <summary>
        /// This method is used to retrieve the account records for a single group or for all the groups.
        /// </summary>
        /// <param name="groupId">Contains an group identity value.</param>
        /// <param name="numberOfRecordsToFetch">Contains the number of records to fetch.</param>
        /// <returns>Returns a list of <see cref="UserClaim"></see> records, if found.</returns>
        public async Task<List<ReportUserModel>> AccountEntriesAsync(Guid groupId, int numberOfRecordsToFetch)
        {
            var results = this.Context.DataContext.Users
                .AsNoTracking()
                .Join(this.Context.DataContext.GroupUsers, u => u.Id, ou => ou.UserId, (u, ou) => new { User = u, GroupUser = ou })
                .OrderByDescending(u => u.User.CreatedDate)
                .Take(numberOfRecordsToFetch)
                .AsQueryable();

            if (groupId != Guid.Empty)
            {
                results = results.Where(ou => ou.GroupUser.GroupId == groupId);
            }

            return await results.Select(u => new ReportUserModel
            {
                UserId = u.User.Id,
                CreatedDate = u.User.CreatedDate,
                Email = u.User.Email,
                FirstName = this.Context.DataContext.UserClaims.Where(uc => uc.UserId == u.User.Id && uc.ClaimType == JwtClaimTypes.GivenName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty,
                LastName = this.Context.DataContext.UserClaims.Where(uc => uc.UserId == u.User.Id && uc.ClaimType == JwtClaimTypes.FamilyName).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty,
                LastLoginDateTime = u.User.LastLoginDate,
                Picture = this.Context.DataContext.UserClaims.Where(uc => uc.UserId == u.User.Id && uc.ClaimType == JwtClaimTypes.Picture).Select(uc => uc.ClaimValue).FirstOrDefault() ?? string.Empty,
                UserName = u.User.UserName
            })
            .ToListAsync()
            .ConfigureAwait(false);
        }

        /// <summary>
        /// This method is used to retrieve the number of users for a single group or across all groups.
        /// </summary>
        /// <param name="groupId">Contains an group identity value.</param>
        /// <returns>Returns a count of users.</returns>
        public async Task<int> UsersCountAsync(Guid groupId)
        {
            int result;

            if (groupId != Guid.Empty)
            {
                result = await this.Context.DataContext.GroupUsers.CountAsync(o => o.GroupId == groupId).ConfigureAwait(false);
            }
            else
            {
                result = await this.Context.DataContext.Users.CountAsync().ConfigureAwait(false);
            }

            return result;
        }

        /// <summary>
        /// This method is used to retrieve the number of logins in the last 7 days for a single group or across all groups.
        /// </summary>
        /// <param name="groupId">Contains an group identity value.</param>
        /// <param name="dateSince">Contains the date time to filter the records against.</param>
        /// <returns>Returns the number of logins in the past however many days based on the dateSince parameter.</returns>
        public async Task<int> LoginsCountAsync(Guid groupId, DateTime dateSince)
        {
            int results;

            if (groupId != Guid.Empty)
            {
                results = await this.Context.DataContext.AuditLogs
                            .AsNoTracking()
                            .Join(this.Context.DataContext.GroupUsers, ou => ou.UserId, sl => sl.UserId, (sl, ou) => new { GroupUser = ou, AuditLog = sl })
                            .Where(sl => sl.AuditLog.EventDateTime >= dateSince && sl.AuditLog.Event == AuditEvent.Login && sl.AuditLog.Result == AuditResult.Success &&
                                sl.GroupUser.GroupId == groupId)
                            .CountAsync();
            }
            else
            {
                results = await this.Context.DataContext.AuditLogs
                    .AsNoTracking()
                    .CountAsync(l => l.EventDateTime >= dateSince && l.Event == AuditEvent.Login && l.Result == AuditResult.Success);
            }

            return results;
        }

        /// <summary>
        /// This method is used to retrieve the number of new accounts created in the last 7 days for a single group or across all groups.
        /// </summary>
        /// <param name="groupId">Contains an group identity value.</param>
        /// <param name="dateSince">Contains the date time to filter the records against.</param>
        /// <returns>Returns the number of accounts created in the past however many days based on the dateSince parameter.</returns>
        public async Task<int> NewAccountsCountAsync(Guid groupId, DateTime dateSince)
        {
            int result;

            if (groupId != Guid.Empty)
            {
                result = await this.Context.DataContext.Users
                    .AsNoTracking()
                    .Join(this.Context.DataContext.GroupUsers, u => u.Id, ou => ou.UserId, (u, ou) => new { GroupUser = ou, User = u })
                    .CountAsync(u => u.User.CreatedDate >= dateSince && u.GroupUser.GroupId == groupId)
                    .ConfigureAwait(false);
            }
            else
            {
                result = await this.Context.DataContext.Users.CountAsync(u => u.CreatedDate >= dateSince).ConfigureAwait(false);
            }

            return result;
        }
    }
}