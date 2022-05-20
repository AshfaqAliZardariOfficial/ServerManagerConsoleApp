using Certes;
using Certes.Acme;
using Microsoft.Web.Administration;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServerManagerConsoleApp
{
    class Program
    {
        private static readonly string _aCMEAccountKeyPath = "ACMEAccountKey.txt";
        private static readonly string _exceptionLogFilePath = "Exceptions.txt";
        private static readonly string _aCMEAccountEmail = "ashfaqalizardariofficial@gmail.com";
        private static readonly string _domain = "zardaristudioinc.cf";
        private static readonly string _tokenPath = "C:\\inetpub\\wwwroot\\AAZ_SSL_Demo\\.well-known\\acme-challenge\\";
        private static readonly string _directoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";
        private static string _newNonceUrl = null;
        private static string _newAccountUrl = null;
        // https://letsencrypt.org/certificates/
        // https://letsencrypt.org/certs/isrgrootx1.pem
        //private static readonly string _letsencryptIssuerPemFilePath = "isrgrootx1.pem";
        static readonly char[] padding = { '=' };
        static void Main(string[] args)
        {
            var Urls = GetDirectoryUrlsDictionary();
            _newNonceUrl = Urls != null && Urls.Count() > 0 && Urls.ContainsKey("newNonce") ? Urls["newNonce"].ToString() : null;
            _newAccountUrl = Urls != null && Urls.Count() > 0 && Urls.ContainsKey("newAccount") ? Urls["newAccount"].ToString() : null;
            // RSAKeys.runTests();

            // JWS Protected Header
            // - JWS Web Key (JWK)
            // Generate a public/private key pair.
            RSACryptoServiceProvider _initialProvider = new RSACryptoServiceProvider(4096);

            string _privateKeyPath = "PrivateKey.xml";
            string _publicKeyPath = "PublicKey.xml";
            string _privateKey = null;
            if (!FileManager.IsFileExist(filePath: _privateKeyPath))
            {
                _privateKey = RSAKeys.ExportPrivateKey(_initialProvider);
                FileManager.WriteMessage(message: _privateKey, filePath: _privateKeyPath, appendMessage: false);
            }

            if (!FileManager.IsFileExist(filePath: _publicKeyPath))
            {
                string _publicKey = null;
                _publicKey = RSAKeys.ExportPublicKey(_initialProvider);
                FileManager.WriteMessage(message: _publicKey, filePath: _publicKeyPath, appendMessage: false);
            }
            _privateKey = FileManager.ReadMessage(filePath: _privateKeyPath);
            RSACryptoServiceProvider _importedProvider = RSAKeys.ImportPrivateKey(_privateKey);
            //_privateKey = RSAKeys.ExportPrivateKey(_importedProvider);
            //_publicKey = RSAKeys.ExportPublicKey(_importedProvider);


            byte[] _publicExponent = _importedProvider.ExportParameters(false).Exponent;
            byte[] _publicModulus = _importedProvider.ExportParameters(false).Modulus;


            //string _kty = "RSA"; /* Key Type */
            string _base64EncodePublicExponent = Base64Encode(_publicExponent);
            string _base64EncodePublicModulus = Base64Encode(_publicModulus);

            var jwk = new Dictionary<string, object>
            {
                { "e", _base64EncodePublicExponent},
                { "kty", "RSA" },
                { "n", _base64EncodePublicModulus }
            };
            //string _jwk = JsonConvert.SerializeObject(jwk);
            string _nonce = GetNonceString(_newNonceUrl);

            var jws = new Dictionary<string, object>
            {
                { "alg", "RS256"},
                { "jwk", jwk},
                { "nonce", _nonce },
                { "url", _newAccountUrl }
            };
            string _jws = JsonConvert.SerializeObject(jws, Formatting.Indented);
            string _protectedBase64Encode = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(_jws));

            var payload = new Dictionary<string, object>
            {
                { "termsOfServiceAgreed", true},
                { "contact", new string[]{ "mailto:me@gmail.com" } }
            };
            string strPayload = JsonConvert.SerializeObject(payload);
            string _payloadBase64Encode = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(strPayload));

            // Hash and sign the data.
            //byte[] signedData = HashAndSignBytes(bytes, _importedProvider.ExportParameters(true));
            byte[] signedData = _importedProvider.SignData(Encoding.ASCII.GetBytes(strPayload),HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            string _signatureBase64Encode = Base64Encode(signedData);

            var _requestBodyPrms = new Dictionary<string, string>
            {
                { "protected", _protectedBase64Encode},
                { "payload", _payloadBase64Encode },
                { "signature", _signatureBase64Encode }
            };
            string _requestBody = JsonConvert.SerializeObject(_requestBodyPrms);

            var client = new RestClient(_newAccountUrl);
            var request = new RestRequest();
            request.Method = Method.Post;
            request.AddHeader("Content-Type", "application/jose+json");
            request.AddBody(_requestBody, "application/jose+json");
            var response = client.ExecuteAsync(request).Result;
            Console.WriteLine(response.Content);

            Console.WriteLine();
            //try
            //{

            //    FileManager.WriteMessage(message: Environment.NewLine);
            //    FileManager.WriteMessage(message: Environment.NewLine);

            //    // Create ACME account if not exist.
            //    CreateAcmeAccount(EmailAddress: _aCMEAccountEmail);

            //    // Use an existing ACME account.
            //    IAcmeContext acme = UseExistingACMEAccount().GetAwaiter().GetResult();

            //    IOrderContext order = null;
            //    // HTTP Challenge.
            //    if (acme != null)
            //    {
            //        order = CreateOrder(acme, _domain).GetAwaiter().GetResult();
            //    }

            //    IChallengeContext challenge = null;
            //    if (order != null)
            //    {
            //        challenge = Authorization(order).GetAwaiter().GetResult();
            //    }

            //    // validate.
            //    if (challenge != null)
            //    {
            //        Validate(challenge, order, siteName: "AAZ_SSL_Demo");
            //    }
            //}
            //catch (Exception ex)
            //{
            //    string _timeZone = "Pakistan Standard Time";
            //    string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            //    FileManager.WriteMessage(message: $"{_pkDateTime} {Environment.NewLine} Exception: {ex.Message} {Environment.NewLine} StackTrace: {ex.StackTrace} {Environment.NewLine}", filePath: _exceptionLogFilePath);
            //}
            //Console.WriteLine("Check log file.");
            Console.ReadKey();
        }

        private static string GetNonceString(string newNonceUrl)
        {
            string _nonce = null;
            HttpResponseMessage response = new HttpClient().GetAsync(newNonceUrl).GetAwaiter().GetResult();
            if (response.Headers.Contains("Replay-Nonce"))
            {
                _nonce = response.Headers.GetValues("Replay-Nonce").First();
            }
            return _nonce;
        }
        private static Dictionary<string, object> GetDirectoryUrlsDictionary()
        {
            Dictionary<string, object> ResponseParams = null;
            HttpResponseMessage response = new HttpClient().GetAsync(_directoryUrl).GetAwaiter().GetResult();
            if (response != null)
            {
                var responJsonText = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                ResponseParams = JsonConvert.DeserializeObject<Dictionary<string, object>>(responJsonText);
            }
            return ResponseParams;
        }

        private static void CreateAcmeAccount(string EmailAddress)
        {
            string _timeZone = "Pakistan Standard Time";
            string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            if (FileManager.IsFileExist(_aCMEAccountKeyPath))
            {
                FileManager.WriteMessage(message: _pkDateTime + " ACME Account exist.");
            }
            else
            {
                _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + " Creating ACME Account.");
                // Creating new ACME account.
                var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
                var account = acme.NewAccount(EmailAddress, true).GetAwaiter().GetResult();
                // Save the account key for later use
                var pemKey = acme.AccountKey.ToPem();
                FileManager.WriteMessage(message: pemKey, filePath: _aCMEAccountKeyPath, useProjectRootDirectory: true, appendMessage: false);
                _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + " ACME Account created.");
            }

        }

        private static async Task<IAcmeContext> UseExistingACMEAccount()
        {
            IAcmeContext acme = null;
            string _timeZone = "Pakistan Standard Time";
            if (!FileManager.IsFileExist(_aCMEAccountKeyPath))
            {
                string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + " existing ACME account key not found.");
            }
            else
            {
                string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + " getting existing ACME account.");
                string pemKey = FileManager.ReadMessage(filePath: _aCMEAccountKeyPath);
                var accountKey = KeyFactory.FromPem(pemKey);
                acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, accountKey);
                _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + " success get ACME existing account.");
                var Account = await acme.Account();
            }
            return acme;
        }

        private static async Task<IOrderContext> CreateOrder(IAcmeContext acme, string domain)
        {
            string _timeZone = "Pakistan Standard Time";
            string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " Creating order for domain: " + domain);
            var order = await acme.NewOrder(new[] { domain });
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " order for domain: " + domain + " created.");

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " generating authorization key.");
            return order;
        }

        private static async Task<IChallengeContext> Authorization(IOrderContext order)
        {
            string _timeZone = "Pakistan Standard Time";
            //// Authorization
            var authz = (await order.Authorizations()).First();
            var httpChallenge = await authz.Http();
            var token = httpChallenge.Token;
            var keyAuthz = httpChallenge.KeyAuthz;
            string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " authorization key generated.");

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " writing authorize key as file.");
            FileManager.WriteMessage(message: keyAuthz, filePath: _tokenPath + token, useProjectRootDirectory: false);
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " authorize key written success in a file: " + token);
            return httpChallenge;
        }

        private static async void Validate(IChallengeContext challenge, IOrderContext order, string siteName)
        {
            string _timeZone = "Pakistan Standard Time";
            string _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " validating...");

            var ch = await challenge.Validate();
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " validate status: " + ch.Status);


            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " retrying validate. ");

            var chR = await challenge.Resource();
            while (chR.Status != Certes.Acme.Resource.ChallengeStatus.Valid && chR.Status != Certes.Acme.Resource.ChallengeStatus.Invalid)
            {
                _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                FileManager.WriteMessage(message: _pkDateTime + $" httpChallenge status : {chR.Status}, retry in 4 seconds.");
                Thread.Sleep(4000);
                chR = await challenge.Resource();
            }
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " validate status: " + chR.Status);

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " Generating certificate.");
            // Generate certificate.
            // Download the certificate once validation is done

            //_pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            //// https://letsencrypt.org/certs/isrgrootx1.pem
            //FileManager.WriteMessage(message: _pkDateTime + " reading letsencrypt Root Certificate ISRG Root X1 pem file.");

            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            //string letsencryptRootCertificateISRGRootX1pemString = FileManager.ReadMessage(_letsencryptIssuerPemFilePath);
            //_pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            //// https://letsencrypt.org/certs/isrgrootx1.pem
            //FileManager.WriteMessage(message: _pkDateTime + " letsencrypt Root Certificate ISRG Root X1 pem file string:" + letsencryptRootCertificateISRGRootX1pemString);

            //privateKey = KeyFactory.FromDer(Convert.FromBase64String(@"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc="));
            //_pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            //FileManager.WriteMessage(message: _pkDateTime + " Letsencrypt issuer pem file read success.");

            var cert = await order.Generate(new CsrInfo
            {
                CountryName = "R3",
                State = "",
                Locality = "",
                Organization = "Let's Encrypt",
                OrganizationUnit = "",
                CommonName = _domain,
            }, privateKey);
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " certificate generated success.");

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " writing certificate to file.");
            // Export full chain certification.
            var certPem = cert.ToPem();
            FileManager.WriteMessage(message: certPem, "certificate.txt", appendMessage: false);

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " certificate file written success.");

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " getting certificate PFX.");
            // Export PFX.
            string password = "abcd1234";
            var pfxBuilder = cert.ToPfx(privateKey);

            var pfx = pfxBuilder.Build("my-cert", password);
            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " certificate PFX get success.");

            _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
            FileManager.WriteMessage(message: _pkDateTime + " adding certificate to site.");
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

            // Here, directory is my install dir, and (directory)\bin\certificate.pfx is where the cert file is.
            // 1234 is the password to the certfile (exported from IIS)
            //X509Certificate2 certificate = new X509Certificate2(directory + @"\bin\certificate.pfx", "1234");
            X509Certificate2 certificate = new X509Certificate2(pfx, password);

            store.Add(certificate);
            if (IsSiteExists(siteName))
            {
                using (ServerManager serverManager = new ServerManager())
                {
                    if (serverManager != null)
                    {
                        Site site = serverManager.Sites[siteName];
                        var binding = site.Bindings.Add("*:443:", certificate.GetCertHash(), store.Name);
                        binding.Protocol = "https";
                        //serverManager.Sites[SiteName].Bindings.Add(BindingInformation, BindingProtocol);
                        serverManager.CommitChanges();
                        _pkDateTime = string.Format("{1} ({0})", _timeZone, TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTimeOffset.UtcNow, _timeZone).ToString("dd/MM/yyyy hh:mm:ss tt zzz"));
                        FileManager.WriteMessage(message: _pkDateTime + " certificate added to site success.");

                    }
                }
            }
            store.Close();

        }

        //private SiteCollection GetSites()
        //{
        //    using (ServerManager serverManager = new ServerManager())
        //    {
        //        if (serverManager != null)
        //        {

        //            return serverManager.Sites;
        //        }
        //        return null;
        //    }
        //}
        //private static Site GetSite(string SiteName)
        //{
        //    Site site = null;
        //    using (ServerManager serverManager = new ServerManager())
        //    {
        //        if (serverManager != null)
        //        {
        //            site = serverManager.Sites[SiteName];
        //        }
        //    }
        //    return site;
        //}
        private static bool IsSiteExists(string SiteName)
        {
            bool flagset = false;
            using (ServerManager serverManager = new ServerManager())
            {
                if (serverManager != null)
                {
                    foreach (Site site in serverManager.Sites)
                    {
                        if (site.Name == SiteName.ToString())
                        {
                            flagset = true;
                            break;
                        }
                        else
                        {
                            flagset = false;
                        }
                    }
                }
            }
            return flagset;
        }

        //private bool CreateSite(string SiteName, int Port = 80, string PhysicalPath = null)
        //{
        //    bool flagset = false;
        //    using (ServerManager serverManager = new ServerManager())
        //    {
        //        PhysicalPath = string.IsNullOrEmpty(PhysicalPath) ? "c:\\inetpub\\wwwroot\\" + SiteName : PhysicalPath + SiteName;
        //        Site mySite = serverManager.Sites.Add(SiteName, PhysicalPath, Port);
        //        mySite.ServerAutoStart = true;
        //        serverManager.CommitChanges();
        //        flagset = IsSiteExists(SiteName);
        //    }
        //    return flagset;
        //}
        //private void CreateApplicationPool(string ApplicationPool)
        //{
        //    using (ServerManager serverManager = new ServerManager())
        //    {
        //        //Site site = serverManager.Sites[SiteName];
        //        //site.Name = SiteName;
        //        //site.Applications[0].VirtualDirectories[0].PhysicalPath = "d:\\racing";
        //        serverManager.ApplicationPools.Add(ApplicationPool);
        //        //serverManager.Sites["Racing Site"].Applications[0].ApplicationPoolName = ApplicationPool;
        //        ApplicationPool apppool = serverManager.ApplicationPools[ApplicationPool];
        //        apppool.ManagedPipelineMode = ManagedPipelineMode.Integrated;
        //        serverManager.CommitChanges();
        //        apppool.Recycle();
        //    }
        //}
        private static void AddBindingInSite(string SiteName, string BindingInformation, string BindingProtocol)
        {
            if (IsSiteExists(SiteName))
            {
                using (ServerManager serverManager = new ServerManager())
                {
                    if (serverManager != null)
                    {
                        serverManager.Sites[SiteName].Bindings.Add(BindingInformation, BindingProtocol);
                        serverManager.CommitChanges();
                    }
                }
            }
        }

        public static string Base64Encode(byte[] bytes)
        {
            // https://stackoverflow.com/questions/26353710/how-to-achieve-base64-url-safe-encoding-in-c
            string returnValue = Convert.ToBase64String(bytes)
            .TrimEnd(padding).Replace('+', '-').Replace('/', '_');
            // with:static readonly char[] padding = { '=' };

            // and to reverse:
            //string incoming = returnValue
            //.Replace('_', '/').Replace('-', '+');
            //switch (returnValue.Length % 4)
            //{
            //    case 2: incoming += "=="; break;
            //    case 3: incoming += "="; break;
            //}
            //byte[] bytes = Convert.FromBase64String(incoming);
            //string originalText = Encoding.ASCII.GetString(bytes);
            return returnValue;
        }
        //public static string Base64Decode(string base64EncodedData)
        //{
        //    var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
        //    return Encoding.UTF8.GetString(base64EncodedBytes);
        //}
        //public static string Base64Decode(byte[] base64EncodedData)
        //{
        //    return Encoding.UTF8.GetString(base64EncodedData);
        //}
        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the
                // key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(4096);

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.SignData(DataToSign, SHA256.Create());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }
    }
}
