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
    using System.Net;
    using System.Security.Cryptography;
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
                if (!string.IsNullOrEmpty(settings.Thumbprint))
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
                else if (settings.GenerateSelfSigning)
                {
                    Certificate = GenerateSelfSignedServerCertificate(password: Properties.Resources.ApplicationName);
                }
            }

            return Certificate;
        }

        /// <summary>
        /// Generates the self signed server certificate.
        /// </summary>
        /// <param name="certificateName">Contains the certificate name.</param>
        /// <param name="password">Contains the password.</param>
        /// <returns>Returns a <see cref="X509Certificate2" /> certificate.</returns>
        public static X509Certificate2 GenerateSelfSignedServerCertificate(string certificateName = "self-signed-cert", string password = "")
        {
            X509Certificate2 result = null;
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);

            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={certificateName}");

            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));

                request.CertificateExtensions.Add(
                   new X509EnhancedKeyUsageExtension(
                       new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                //certificate.FriendlyName = certificateName;

                result = new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, X509KeyStorageFlags.MachineKeySet);
            }

            return result;
        }
    }
}