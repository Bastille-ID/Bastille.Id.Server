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

namespace Bastille.Id.Server
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Threading;
    using Bastille.Id.Core;
    using Bastille.Id.Core.Configuration;
    using Bastille.Id.Core.Data;
    using Bastille.Id.Core.Data.Entities;
    using Bastille.Id.Server.Core.Configuration;
    using Bastille.Id.Server.Core.Data;
    using Bastille.Id.Server.Core.Identity;
    using IdentityServer4;
    using IdentityServer4.EntityFramework.DbContexts;
    using Microsoft.ApplicationInsights.Extensibility;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.StaticFiles;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.IdentityModel.Tokens;
    using Serilog;
    using Talegen.AspNetCore.hCAPTCHA;
    using Talegen.Common.Core.Errors;
    using Talegen.Common.Core.Extensions;
    using Talegen.Common.Messaging;
    using Vasont.AspnetCore.RedisClient;

    /// <summary>
    /// This class contains the main startup routines for the web application.
    /// </summary>
    public class Startup
    {
        #region Private Fields

        /// <summary>
        /// The account error URL
        /// </summary>
        private const string AccountErrorUrl = "/Account/Error";

        /// <summary>
        /// Contains an instance of the application settings.
        /// </summary>
        private ApplicationSettings applicationSettings;

        /// <summary>
        /// Contains the identity server database connection string.
        /// </summary>
        private string databaseConnectionString;

        /// <summary>
        /// Contains the redis cache connection string.
        /// </summary>
        private string redisConnectionString;

        #endregion

        #region Public Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="Startup" /> class.
        /// </summary>
        /// <param name="configuration">Contains an <see cref="IConfiguration" /> implementation.</param>
        /// <param name="environment">Contains an <see cref="IWebHostEnvironment" /> implementation.</param>
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            this.Configuration = configuration;
            this.Environment = environment;
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets the startup configuration.
        /// </summary>
        public IConfiguration Configuration { get; }

        /// <summary>
        /// Gets the hosting environment.
        /// </summary>
        public IWebHostEnvironment Environment { get; }

        /// <summary>
        /// Gets or sets the application settings.
        /// </summary>
        public ApplicationSettings Settings
        {
            get
            {
                if (this.applicationSettings == null)
                {
                    var settingsSection = this.Configuration.GetSection(nameof(ApplicationSettings));
                    this.applicationSettings = settingsSection?.Get<ApplicationSettings>() ?? new ApplicationSettings();
                }

                return this.applicationSettings;
            }
            set
            {
                this.applicationSettings = value;
            }
        }

        /// <summary>
        /// Gets or sets the identity server database connection string.
        /// </summary>
        public string DatabaseConnectionString
        {
            get
            {
                if (string.IsNullOrEmpty(this.databaseConnectionString))
                {
                    this.databaseConnectionString = this.Configuration.GetConnectionString("DefaultConnection");
                }

                return this.databaseConnectionString;
            }

            set
            {
                this.databaseConnectionString = value;
            }
        }

        /// <summary>
        /// Gets or sets the redis cache server connection string.
        /// </summary>
        public string RedisConnectionString
        {
            get
            {
                if (string.IsNullOrEmpty(this.redisConnectionString))
                {
                    this.redisConnectionString = this.Configuration.GetConnectionString("RedisConnection");
                }

                return this.redisConnectionString;
            }

            set
            {
                this.redisConnectionString = value;
            }
        }

        #endregion

        #region Public Startup Methods

        /// <summary>
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        /// <param name="services">Contains the service collection.</param>
        public void ConfigureServices(IServiceCollection services)
        {
            bool development = this.Environment.IsDevelopment();

            this.InitializeSettings(services);

            ConfigureServiceStartupSettings(this.Settings, this.Environment.ContentRootPath, this.RedisConnectionString);

            // setup service injection
            ConfigureServiceInjectionObjects(services, this.Settings, this.DatabaseConnectionString);

            // setup server
            ConfigureServiceWebServer(services, this.Settings, this.RedisConnectionString, development);

            // configure data protection services
            ConfigureServiceDataProtectionServices(services, this.Settings, development);

            // configure the identity server middleware
            ConfigureServiceIdentityServer(services, this.Settings, this.DatabaseConnectionString);

            // initialize the database if auto-migrate is configured....
            if (this.Settings.Advanced.AutoMigrate)
            {
                // initialize the database via migrations.
                InitializeDatabase(services, development);
            }

            // configure any external authenticator configurations for external authentication
            ConfigureServiceExternalAuthenticators(services, this.Settings);

            // add background messaging
            services.AddMessaging(this.Settings.Messaging);
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        /// <param name="app">Contains the application builder.</param>
        /// <param name="env">Contains the hosting environment.</param>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseExceptionHandler(AccountErrorUrl);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHsts();
            app.UseSession();

            if (this.Settings.Advanced.ForceSsl)
            {
                app.UseHttpsRedirection();
            }

            this.EnableStaticFiles(app);

            // add cookie policy
            app.UseCookiePolicy();

            // start the identity server.
            app.UseIdentityServer();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Account}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

        #endregion

        #region Private Configure Service Methods

        /// <summary>
        /// Initializes the settings.
        /// </summary>
        /// <param name="services">The services.</param>
        private void InitializeSettings(IServiceCollection services)
        {
            services
                .Configure<ApplicationSettings>(this.Configuration.GetSection(nameof(ApplicationSettings)))
                .PostConfigure<ApplicationSettings>(options =>
                {
                    // setup working folder if none specified
                    if (string.IsNullOrWhiteSpace(options.Storage.RootPath))
                    {
                        // working folder will reside in the main application folder by default.
                        options.Storage.RootPath = Path.Combine(this.Environment.ContentRootPath, options.Advanced.AppDataSubFolderName);
                    }
                });

            // configure telemetry settings
            ConfigureServiceTelemetry(services, this.Settings);

            // show connection strings if diagnosing
            if (this.Settings.Advanced.ShowDiagnostics || this.Environment.IsDevelopment())
            {
                // show PII in logging - by default useful PII is stripped out
                Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;

                Log.Debug("Connection String: {0}\r\nRedis String: {1}", this.DatabaseConnectionString, this.RedisConnectionString);
            }
        }

        /// <summary>
        /// Configures the telemetry for the application.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        private static void ConfigureServiceTelemetry(IServiceCollection services, ApplicationSettings settings)
        {
            services.AddSingleton<ITelemetryInitializer, InstrumentationConfigInitializer>();
            services.AddApplicationInsightsTelemetry(settings.ApplicationInsights.InstrumentationKey);
        }

        /// <summary>
        /// Configures the startup settings.
        /// </summary>
        /// <param name="settings">The settings.</param>
        /// <param name="contentRootPath">Content root path.</param>
        /// <param name="redisConnectionString">Contains the redis connection string.</param>
        private static void ConfigureServiceStartupSettings(ApplicationSettings settings, string contentRootPath, string redisConnectionString)
        {
            // setup working folder if none specified
            if (string.IsNullOrWhiteSpace(settings.Storage.RootPath))
            {
                // working folder will reside in the main application folder by default.
                settings.Storage.RootPath = Path.Combine(contentRootPath, settings.Advanced.AppDataSubFolderName);
            }

            // if thread settings config has a value...
            if (settings.Advanced.MinimumCompletionPortThreads > 0)
            {
                // setup threading
                ThreadPool.GetMinThreads(out int workerThreads, out int completionPortThreads);
                ThreadPool.SetMinThreads(workerThreads * 2, completionPortThreads > settings.Advanced.MinimumCompletionPortThreads ? completionPortThreads : settings.Advanced.MinimumCompletionPortThreads);
            }

            if (!string.IsNullOrWhiteSpace(redisConnectionString))
            {
                // setup Redis
                RedisManager.Initialize(redisConnectionString);
            }
        }

        /// <summary>
        /// Configures the injection objects.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="connectionString">The connection string.</param>
        private static void ConfigureServiceInjectionObjects(IServiceCollection services, ApplicationSettings settings, string connectionString)
        {
            // define the direct inject for the Application Database Context
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(connectionString);
            });

            // add injections
            services.AddTransient<IErrorManager, ErrorManager>();

            // add security provider define the identity user model and data store information
            services.AddIdentity<User, Role>(options =>
            {
                options.Password.RequiredLength = settings.Account.Passwords.RequiredLength;
                options.Password.RequireDigit = settings.Account.Passwords.RequireDigit;
                options.Password.RequiredUniqueChars = settings.Account.Passwords.RequiredUniqueChars;
                options.Password.RequireLowercase = settings.Account.Passwords.RequireLowercase;
                options.Password.RequireNonAlphanumeric = settings.Account.Passwords.RequireNonAlphanumeric;
                options.Password.RequireUppercase = settings.Account.Passwords.RequireUppercase;
                options.User.RequireUniqueEmail = settings.Account.RequireUniqueEmail;
                options.SignIn.RequireConfirmedAccount = true;
                options.SignIn.RequireConfirmedEmail = !settings.Account.AllowSignInBeforeEmailVerification;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            // setup transient for application settings.
            services.AddTransient<ApplicationContext<ApplicationSettings>>();
        }

        /// <summary>
        /// Configures the web server.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="redisConnectionString">The redis connection string.</param>
        /// <param name="development">Contains a value indicating whether the application is in a dev environment.</param>
        private static void ConfigureServiceWebServer(IServiceCollection services, ApplicationSettings settings, string redisConnectionString, bool development)
        {
            // add session
            services.AddSession(opts =>
            {
                opts.Cookie.IsEssential = true; // make the session cookie Essential
            });

            // Add hCAPTCHA middleware with settings.
            services.AddHCaptcha(settings.Captcha);

            // setup MVC
            services
                .AddControllersWithViews(options =>
                {
                    // add hCAPTCHA model binder
                    options.AddHCaptchaModelBinder();
                });
            services.AddRazorPages()
                .AddNewtonsoftJson(setup =>
                {
                    setup.SerializerSettings.Formatting = development ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None;
                    setup.SerializerSettings.DateTimeZoneHandling = Newtonsoft.Json.DateTimeZoneHandling.Utc;
                    setup.SerializerSettings.StringEscapeHandling = Newtonsoft.Json.StringEscapeHandling.EscapeNonAscii;
                    setup.SerializerSettings.ContractResolver = new Newtonsoft.Json.Serialization.DefaultContractResolver();
                })
                .AddSessionStateTempDataProvider();

            // configure the web server security settings
            ConfigureServiceWebServerSecurity(services, settings, development);

            // choose cache mechanism
            if (!string.IsNullOrEmpty(redisConnectionString))
            {
                // use the Redis mechanism
                services.AddRedisClientCache(options =>
                {
                    options.Configuration = redisConnectionString;
                });
            }
            else
            {
                // use local memory
                services.AddMemoryCache();
                services.AddDistributedMemoryCache();
            }

            // adds services for using options
            services.AddOptions();
        }

        /// <summary>
        /// Configures the web server security.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="development">Contains a value indicating whether the application is in a dev environment.</param>
        private static void ConfigureServiceWebServerSecurity(IServiceCollection services, ApplicationSettings settings, bool development)
        {
            // if we're forcing SSL...
            if (settings.Advanced.ForceSsl)
            {
                services.Configure<MvcOptions>(options => { options.Filters.Add(new RequireHttpsAttribute()); });
            }

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.Secure = CookieSecurePolicy.SameAsRequest;

                // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1
                HandleSameSiteCookieCompatibility(options);
            });

            services.ConfigureApplicationCookie(configure =>
            {
                configure.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                configure.Cookie.SameSite = SameSiteMode.None;
            });

            // setup HSTS settings
            services.AddHsts(options =>
            {
                options.IncludeSubDomains = true;
                options.MaxAge = development ? TimeSpan.FromMinutes(60) : TimeSpan.FromDays(365);
            });

            // Configure the Default CORS configuration.
            services.AddCors(options =>
            {
                options.AddPolicy("default",
                    policy =>
                    {
                        policy.AllowAnyMethod();
                        policy.AllowAnyHeader();

                        // if origins defined, restrict them.
                        if (settings.Security.AllowedOrigins.Any())
                        {
                            policy.WithOrigins(settings.Security.AllowedOrigins.ToArray())
                                .SetIsOriginAllowedToAllowWildcardSubdomains()
                                .AllowCredentials();
                        }
                        else
                        {
                            // otherwise allow any, but most browsers will not allow loading of content.
                            policy.AllowAnyOrigin();
                        }

                        // For CSV or any file download need to expose the headers, otherwise in JavaScript response.getResponseHeader('Content-Disposition')
                        // retuns undefined https://stackoverflow.com/questions/58452531/im-not-able-to-access-response-headerscontent-disposition-on-client-even-aft
                        policy.WithExposedHeaders("Content-Disposition");
                    });
            });
        }

        /// <summary>
        /// Configures the data protection services.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="development">Contains a value indicating whether app is running in development environment.</param>
        private static void ConfigureServiceDataProtectionServices(IServiceCollection services, ApplicationSettings settings, bool development)
        {
            var dataProtectionService = services.AddDataProtection()
                .SetDefaultKeyLifetime(TimeSpan.FromDays(settings.Security.DataPersistence.PersistenceLengthDays))
                .SetApplicationName(Properties.Resources.ApplicationName);

            // based on the storage method, configure data persistence storage
            switch (settings.Security.DataPersistence.Method)
            {
                case DataPersistenceStorageMethod.Redis:
                    Log.Information("Persisting data to Redis");
                    dataProtectionService.PersistKeysToStackExchangeRedis(RedisManager.Connection, "DataProtection-Keys");
                    break;

                case DataPersistenceStorageMethod.FileSystem:

                    if (!development)
                    {
                        Log.Warning("File system persistance should not be used.");
                    }

                    // add data protection with a specific folder to share across a farm. Do note that to remain secure, the folder must have full permissions
                    // for the web application user and no other user.
                    if (!string.IsNullOrWhiteSpace(settings.Security.DataPersistence.FolderPath))
                    {
                        Log.Information("Persisting data to folder {0}", settings.Security.DataPersistence.FolderPath);

                        // add local file system persistence storage
                        dataProtectionService
                            .PersistKeysToFileSystem(new DirectoryInfo(settings.Security.DataPersistence.FolderPath));

                        Log.Information("Environment Version: {0}", RuntimeInformation.OSDescription);

                        // we must protect our keys!

                        // we will protect keys using a certificate
                        if (!string.IsNullOrWhiteSpace(settings.Security.DataPersistence.Thumbprint))
                        {
                            dataProtectionService.ProtectKeysWithCertificate(CertificateExtensions.RetrieveCertificate(settings.Security.SigningKey));
                        }
                        else if (!development)
                        {
                            // no thumbail specified! We will lose keys after every run. :| develop mode only.
                            Log.Warning("No certificate specified for Data Persistance Protection.");
                        }
                    }

                    break;

                    ////case DataPersistenceStorageMethod.AzureVault:
                    ////    Log.Information("Persisting data to Azure Vault");
                    ////    dataProtectionService.ProtectKeysWithAzureKeyVault(new Uri(settings.Security.DataPersistence.AzureBlobUriWithToken, new Azure.Identity.DefaultAzureCredential()));
                    ////    break;
            }
        }

        /// <summary>
        /// Configures the identity server.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="connectionString">The connection string.</param>
        private static void ConfigureServiceIdentityServer(IServiceCollection services, ApplicationSettings settings, string connectionString)
        {
            // get the assembly that contains the database migrations information
            var migrationsAssembly = typeof(ApplicationDbContext).GetTypeInfo().Assembly.GetName().Name;

            // register the IdentityServer services in DI.
            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.UserInteraction.ErrorIdParameter = "RequestId";
                options.UserInteraction.ErrorUrl = AccountErrorUrl;
            })
                .AddAspNetIdentity<User>()
                .AddConfigurationStore(options =>
                {
                    // setup the db context
                    options.ConfigureDbContext = b => b.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    // setup the db context
                    options.ConfigureDbContext = b => b.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationsAssembly));

                    // this enables automatic token cleanup.
                    options.EnableTokenCleanup = true;

                    // frequency in seconds to cleanup state grants. 15 is useful during debugging
                    options.TokenCleanupInterval = settings.Advanced.TokenCleanupIntervalSeconds;
                });

            // add custom delegation grant type token validator
            builder.AddExtensionGrantValidator<DelegationGrantValidator>();

            // add signing certificate
            builder.AddCertificateFromStore(settings.Security.SigningKey);
        }

        /// <summary>
        /// Configures the external authenticators.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> services.</param>
        /// <param name="settings">The <see cref="ApplicationSettings" /> settings.</param>
        private static void ConfigureServiceExternalAuthenticators(IServiceCollection services, ApplicationSettings settings)
        {
            // add authentication
            AuthenticationBuilder authenticationBuilder = services.AddAuthentication();
            ServiceProvider provider = services.BuildServiceProvider();

            try
            {
                // get all providers with a client id specified...
                settings.Account.ExternalProviders.Where(p => !string.IsNullOrWhiteSpace(p.ClientId)).ToList().ForEach(externalProvider =>
                {
                    switch (externalProvider.Provider)
                    {
                        case ExternalAuthenticationProviders.Facebook:
                            authenticationBuilder.AddFacebook(options =>
                            {
                                options.AppId = externalProvider.ClientId;
                                options.AppSecret = externalProvider.ClientSecret;
                            });
                            break;

                        case ExternalAuthenticationProviders.Google:
                            authenticationBuilder.AddGoogle(
                                !string.IsNullOrWhiteSpace(externalProvider.SchemeName) ? externalProvider.SchemeName : ExternalAuthenticationProviders.Google.ToString(),
                                !string.IsNullOrWhiteSpace(externalProvider.DisplayName) ? externalProvider.DisplayName : ExternalAuthenticationProviders.Google.ToString(),
                                options =>
                                {
                                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                                    options.ClientId = externalProvider.ClientId;
                                    options.ClientSecret = externalProvider.ClientSecret;
                                });

                            break;

                        case ExternalAuthenticationProviders.Microsoft:
                            authenticationBuilder.AddMicrosoftAccount(options =>
                            {
                                options.ClientId = externalProvider.ClientId;
                                options.ClientSecret = externalProvider.ClientSecret;
                            });
                            break;

                        case ExternalAuthenticationProviders.Twitter:
                            authenticationBuilder.AddTwitter(options =>
                            {
                                options.ConsumerKey = externalProvider.ClientId;
                                options.ConsumerSecret = externalProvider.ClientSecret;
                                options.RetrieveUserDetails = true;
                            });
                            break;

                        case ExternalAuthenticationProviders.OpenIdConnect:
                            authenticationBuilder
                                .AddOpenIdConnect(
                                    !string.IsNullOrWhiteSpace(externalProvider.SchemeName) ? externalProvider.SchemeName : "oidc",
                                    !string.IsNullOrWhiteSpace(externalProvider.DisplayName) ? externalProvider.DisplayName : Properties.Resources.ApplicationName,
                                    options =>
                                    {
                                        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                                        options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                                        options.Authority = externalProvider.Authority;
                                        options.ClientId = externalProvider.ClientId.Decrypt(settings.Security.AppKey);

                                        if (!string.IsNullOrWhiteSpace(externalProvider.ClientSecret))
                                        {
                                            options.ClientSecret = externalProvider.ClientSecret.Decrypt(settings.Security.AppKey);
                                        }

                                        options.ResponseType = externalProvider.ResponseType;
                                        options.SaveTokens = true;
                                        options.GetClaimsFromUserInfoEndpoint = externalProvider.GetClaimsFromUserInfoEndpoint;
                                        options.CallbackPath = new PathString(externalProvider.CallbackPath);
                                        options.SignedOutCallbackPath = new PathString(externalProvider.SignedOutCallbackPath);
                                        options.RemoteSignOutPath = new PathString(externalProvider.RemoteSignOutPath);

                                        options.TokenValidationParameters = new TokenValidationParameters
                                        {
                                            ValidateIssuer = externalProvider.ValidateIssuer,
                                            NameClaimType = "name",
                                            RoleClaimType = "role"
                                        };
                                    });

                            break;
                    }
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, Properties.Resources.ExternalProvidersLoadErrorText);
            }
        }

        #endregion

        #region Private Config Methods

        private void EnableSecurityHeaders(IApplicationBuilder app)
        {
            // define the security header policy
            var policyCollection = new HeaderPolicyCollection()
                .AddXssProtectionBlock()
                .AddContentTypeOptionsNoSniff()
                .AddReferrerPolicyNoReferrer()
                .RemoveServerHeader()
                .AddContentSecurityPolicy(builder =>
                {
                    builder.AddObjectSrc().None();
                    builder.AddBaseUri().Self();
                });

            // add security headers to responses.
            app.UseSecurityHeaders(policyCollection);
        }

        /// <summary>
        /// This method is used to enable static files and support additional uncommon extension types.
        /// </summary>
        /// <param name="app">Contains the application builder.</param>
        private void EnableStaticFiles(IApplicationBuilder app)
        {
            // enhance available extensions provided
            var extensionsProvider = new FileExtensionContentTypeProvider();

            if (!extensionsProvider.Mappings.ContainsKey(".woff2"))
            {
                extensionsProvider.Mappings.Add(".woff2", "font/woff2");
            }

            if (!extensionsProvider.Mappings.ContainsKey(".properties"))
            {
                extensionsProvider.Mappings.Add(".properties", "text/properties");
            }

            app.UseStaticFiles(new StaticFileOptions { ContentTypeProvider = extensionsProvider });
        }

        #endregion

        #region Database Support Methods

        /// <summary>
        /// This method is used to execute database migrations as well as initiate some basic start-up data.
        /// </summary>
        /// <param name="services">Contains the services collection.</param>
        /// <param name="development">Contains a value indicating whether the application is in development.</param>
        private static void InitializeDatabase(IServiceCollection services, bool development)
        {
            // Occasionally IdentityServer project will modify the configuration and persisted grant tables. They do not manage the migrations and therefore we
            // must implement our own migrations. Below are the commands to run within the Package Manager Console for Bastille.Id.Core project to generate the
            // correct migrations. !!!NOTE: Ensure that AutoMigrations are disabled in appsettings.Development.json before attempting to run these commands!!!
            //
            // Add-Migration -Name "Identity{MonthAndYear}ConfigurationMigrationChanges" -Context ConfigurationDbContext -OutputDir "Core\Data\Migrations\IdentityServer\ConfigurationDb"
            //
            // To create the PersistedGrantDbContext migration
            //// Add-Migration -Name "Identity{MonthAndYear}PersistedGrantMigrationChanges" -Context PersistedGrantDbContext -OutputDir "Core\Data\Migrations\IdentityServer\PersistedGrantDb"
            using var app = services.BuildServiceProvider();
            using var serviceScope = app.GetService<IServiceScopeFactory>().CreateScope();
            using ApplicationDbContext appContext = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            using PersistedGrantDbContext grantContext = serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>();
            using ConfigurationDbContext configContext = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

            try
            {
                // execute the grant persistence database migrations
                grantContext.Database.Migrate();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred while attempting to migrate the persisted data tables.");
            }

            try
            {
                // execute the configuration database migrations
                configContext.Database.Migrate();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred while attempting to migrate the configuration data tables.");
            }

            try
            {
                // execute the application database migrations
                appContext.Database.Migrate();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred while attempting to migrate the application data tables.");
            }

            // create default user
            try
            {
                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
                var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();

                AsyncHelper.RunSync(() => DataInstallHelpers.InitializeDefaultSecurityDataAsync(appContext, roleManager, userManager));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred while attempting to initialize default user data.");
            }
        }

        #endregion

        #region Private Cookie Policy Methods

        /// <summary>
        /// This method is called to handle the Chrome SameSite issue.
        /// </summary>
        /// <param name="userAgent">Contains the user agent string for the request.</param>
        /// <returns>Returns a value indicating whether disallow same site none.</returns>
        private static bool DisallowsSameSiteNone(string userAgent)
        {
            // Method taken from https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/ Cover all iOS based
            // browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad All of which are broken by SameSite=None, because they use the iOS networking stack.
            return (userAgent.Contains("CPU iPhone OS 12", StringComparison.InvariantCultureIgnoreCase) ||
                userAgent.Contains("iPad; CPU OS 12", StringComparison.InvariantCultureIgnoreCase)) ||

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X. This does not include:
            // - Chrome on Mac OS X Because they do not use the Mac OS networking stack.
            (userAgent.Contains("Macintosh; Intel Mac OS X 10_14", StringComparison.InvariantCultureIgnoreCase) &&
                userAgent.Contains("Version/", StringComparison.InvariantCultureIgnoreCase) && userAgent.Contains("Safari", StringComparison.InvariantCultureIgnoreCase)) ||

            // Cover Chrome 50-69, because some versions are broken by SameSite=None, and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions, but pre-Chromium Edge does not require SameSite=None.
            (userAgent.Contains("Chrome/5", StringComparison.InvariantCultureIgnoreCase) || userAgent.Contains("Chrome/6", StringComparison.InvariantCultureIgnoreCase));
        }

        /// <summary>
        /// Handles SameSite cookie issue the default list of user-agents that disallow SameSite None
        /// </summary>
        /// <param name="options">Contains the cookie policy options.</param>
        /// <returns>Returns new cookie policy options.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3241:Methods should not return values that are never used", Justification = "Reviewed")]
        private static CookiePolicyOptions HandleSameSiteCookieCompatibility(CookiePolicyOptions options)
        {
            // Reference according to the https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1. reference was taken from https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
            return HandleSameSiteCookieCompatibility(options, DisallowsSameSiteNone);
        }

        /// <summary>
        /// Handles SameSite cookie issue according to the docs The default list of user-agents that disallow SameSite None
        /// </summary>
        /// <param name="options">Contains existing cookie policies.</param>
        /// <param name="disallowsSameSiteNone">
        /// If you don't want to use the default user-agent list implementation, the method sent in this parameter will be run against the user-agent and if
        /// returned true, SameSite value will be set to Unspecified.
        /// </param>
        /// <returns>Returns a new Cookie policy.</returns>
        private static CookiePolicyOptions HandleSameSiteCookieCompatibility(CookiePolicyOptions options, Func<string, bool> disallowsSameSiteNone)
        {
            // reference https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1 reference was taken from
            // https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/ The default user-agent list used can be found
            // at: https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.OnAppendCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions, disallowsSameSiteNone);
            options.OnDeleteCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions, disallowsSameSiteNone);

            return options;
        }

        /// <summary>
        /// This method is used to check the same site and set Same Site based on browser.
        /// </summary>
        /// <param name="httpContext">Contains the context.</param>
        /// <param name="options">Contains cookie options.</param>
        /// <param name="disallowsSameSiteNone">Contains a function used to disallow.</param>
        private static void CheckSameSite(HttpContext httpContext, CookieOptions options, Func<string, bool> disallowsSameSiteNone)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                if (disallowsSameSiteNone(userAgent))
                {
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        #endregion
    }
}