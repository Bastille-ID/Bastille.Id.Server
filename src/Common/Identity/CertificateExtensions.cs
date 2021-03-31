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
    using System.Security.Cryptography.X509Certificates;
    using Bastille.Id.Server.Core.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Serilog;

    /// <summary>
    /// This class contains identity server extension methods.
    /// </summary>
    public static class CertificateExtensions
    {
        /// <summary>
        /// Gets or sets the certificate.
        /// </summary>
        /// <value>The certificate.</value>
        private static X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// This method adds to the identity server the certificate store specified for signing.
        /// </summary>
        /// <param name="builder">Contains the identity server builder.</param>
        /// <param name="settings">Contains the configuration certificate options section.</param>
        public static void AddCertificateFromStore(this IIdentityServerBuilder builder, SigningKeySettings settings)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            var cert = RetrieveCertificate(settings);

            if (cert != null)
            {
                builder.AddSigningCredential(cert);
            }
        }

        /// <summary>
        /// Retrieves the certificate.
        /// </summary>
        /// <param name="settings">The settings.</param>
        /// <returns>Returns a <see cref="X509Certificate2" /> certificate if found.</returns>
        public static X509Certificate2 RetrieveCertificate(SigningKeySettings settings)
        {
            if (Certificate == null)
            {
                using (X509Store store = new X509Store(StoreName.My, settings.StoreLocation))
                {
                    store.Open(OpenFlags.ReadOnly);

                    // clean-up any odd unicode characters introduced by MMC console.
                    settings.Thumbprint = settings.Thumbprint.Replace("\u200e", string.Empty)
                        .Replace("\u200f", string.Empty).ToUpperInvariant();

                    try
                    {
                        var certsFound = store.Certificates.Find(X509FindType.FindByThumbprint, settings.Thumbprint, false);

                        if (certsFound.Count > 0)
                        {
                            Log.Information($"Adding key from store by {settings.Thumbprint}");

                            // set static with certificate
                            Certificate = certsFound[0];
                        }
                        else
                        {
                            Log.Information($"A matching key {settings.Thumbprint} couldn't be found in the local certificate store.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, $"An error occurred while attempting to load the certificate with thumbprint {settings.Thumbprint}.");
                    }
                }
            }

            return Certificate;
        }
    }
}