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

namespace Bastille.Id.Server.Core.Configuration
{
    using System;

    /// <summary>
    /// This class contains advanced program settings.
    /// </summary>
    public class AdvancedSettings
    {
        /// <summary>
        /// Gets or sets the home redirect URI that will be used if a user is authenticated and attempting to visit the root address of the server.
        /// </summary>
        /// <remarks>
        /// This allows for separation of concerns in application purpose. The server itself is simply a IndentityServer middleware host. This middleware is for
        /// authentication and validation of tokens. The additional user interfaces added allow for additional means of authentication. Beyond that, the scope
        /// of the application fades. There is really no need to host user management, reporting, etc. in this server application. To that point, we can specify
        /// a URI to an application that can handle those types of interfaces if a ReturlUrl is not specified.
        /// </remarks>
        public Uri HomeRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether consent has enabled offline access.
        /// </summary>
        public bool ConsentEnableOfflineAccess { get; set; } = true;

        /// <summary>
        /// Gets or sets the MinimumCompletionPortThreads count.
        /// </summary>
        public int MinimumCompletionPortThreads { get; set; } = 200;

        /// <summary>
        /// Gets or sets the token clean-up interval in seconds.
        /// </summary>
        public int TokenCleanupIntervalSeconds { get; set; } = 60;

        /// <summary>
        /// Gets or sets the maximum degree of parallelism.
        /// </summary>
        /// <value>The maximum degree of parallelism.</value>
        public int MaxDegreeOfParallelism { get; set; }

        /// <summary>
        /// Gets or sets the memory cache life minutes.
        /// </summary>
        /// <value>The memory cache life minutes.</value>
        public int MemoryCacheLifeMinutes { get; set; } = 10;

        /// <summary>
        /// Gets or sets a value indicating whether the database auto-migration logic should execute on startup.
        /// </summary>
        public bool AutoMigrate { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the server should force SSL only.
        /// </summary>
        public bool ForceSsl { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the diagnostics page is available.
        /// </summary>
        public bool ShowDiagnostics { get; set; }

        /// <summary>
        /// Gets or sets the name of the application data sub folder.
        /// </summary>
        /// <value>The name of the application data sub folder.</value>
        public string AppDataSubFolderName { get; set; } = "App_Data";
    }
}