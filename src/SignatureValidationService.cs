using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MinimalFirewall
{
    public sealed record PublisherSignerIdentity(string DisplayName, string Subject, string Sha256Thumbprint);

    public static class SignatureValidationService
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, IntPtr pgActionID, IntPtr pWinTrustData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pUnion;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_WHOLECHAIN = 1;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_IGNORE = 0;
        private const uint WTD_REVOCATION_CHECK_CHAIN = 0x40;

        public static bool GetPublisherInfo(string filePath, out string? publisherName)
            => IsSignatureTrusted(filePath, out publisherName);

        /// <summary>
        /// Returns a stable signer identity for the publisher allowlist. A valid WinTrust
        /// result is required, and only an embedded Authenticode signer certificate is accepted.
        /// Catalog-signed files remain eligible for the separate OS-trust path, but are not
        /// whitelisted using mutable PE version metadata.
        /// </summary>
        public static bool TryGetTrustedSignerIdentity(
            string filePath,
            out PublisherSignerIdentity? signerIdentity)
        {
            signerIdentity = null;

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath) || !VerifyWithWinTrust(filePath))
            {
                return false;
            }

            signerIdentity = ExtractSignerIdentity(filePath);
            return signerIdentity is not null;
        }

        public static bool IsSignatureTrusted(string filePath, out string? publisherName)
        {
            publisherName = null;

            var core = new SignatureValidationCore(
                new WindowsWinTrustVerifier(),
                ResolveSignerIdentity);

            if (!core.VerifyTrust(filePath))
            {
                return false;
            }

            try
            {
#pragma warning disable SYSLIB0057
                using var basicCert = X509Certificate.CreateFromSignedFile(filePath);
                using var cert = new X509Certificate2(basicCert);
#pragma warning restore SYSLIB0057
                publisherName = NormalizePublisherName(cert.Subject);
            }
            catch (CryptographicException)
            {
                // Catalog-signed: no embedded cert. Preserve the existing PE metadata fallback.
                publisherName = GetPublisherNameFromFileVersion(filePath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Debug.WriteLine($"[INFO] Signer extraction failed for {filePath}: {ex.Message}");
                return false;
            }

            return !string.IsNullOrEmpty(publisherName);
        }

        internal static PublisherSignerIdentity? ResolveSignerIdentity(string filePath)
            => ExtractSignerIdentity(filePath);

        internal static bool VerifyWithWinTrustForSeam(
            string filePath,
            uint revocationChecks,
            uint providerFlags)
            => VerifyWithWinTrust(filePath, revocationChecks, providerFlags);

        private static PublisherSignerIdentity? ExtractSignerIdentity(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                using var basicCert = X509Certificate.CreateFromSignedFile(filePath);
                using var cert = new X509Certificate2(basicCert);
#pragma warning restore SYSLIB0057

                string? displayName = NormalizePublisherName(cert.Subject);
                if (string.IsNullOrWhiteSpace(displayName))
                {
                    return null;
                }

                string sha256Thumbprint = Convert.ToHexString(SHA256.HashData(cert.RawData));
                return new PublisherSignerIdentity(displayName, cert.Subject, sha256Thumbprint);
            }
            catch (CryptographicException)
            {
                // Catalog-signed binaries do not expose an embedded signer certificate through
                // CreateFromSignedFile. Do not fall back to PE CompanyName for allowlisting.
                return null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Debug.WriteLine($"[INFO] Strong signer extraction failed for {filePath}: {ex.Message}");
                return null;
            }
        }

        private static string? NormalizePublisherName(string? subject)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return null;
            }

            const string cnPrefix = "CN=";
            int cnStart = subject.IndexOf(cnPrefix, StringComparison.Ordinal);
            if (cnStart < 0)
            {
                return subject;
            }

            cnStart += cnPrefix.Length;
            int cnEnd = subject.IndexOf(',', cnStart);
            string cn = cnEnd < 0
                ? subject.Substring(cnStart).Trim()
                : subject.Substring(cnStart, cnEnd - cnStart).Trim();

            return string.IsNullOrEmpty(cn) ? subject : cn;
        }

        private static bool VerifyWithWinTrust(string filePath)
            => VerifyWithWinTrust(filePath, WTD_REVOKE_WHOLECHAIN, WTD_REVOCATION_CHECK_CHAIN);

        private static bool VerifyWithWinTrust(
            string filePath,
            uint revocationChecks,
            uint providerFlags)
        {
            IntPtr pFilePath = IntPtr.Zero;
            IntPtr pFileInfo = IntPtr.Zero;
            IntPtr pTrustData = IntPtr.Zero;
            IntPtr pActionId = IntPtr.Zero;

            try
            {
                pFilePath = Marshal.StringToHGlobalUni(filePath);

                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = pFilePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = revocationChecks,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pUnion = pFileInfo,
                    dwStateAction = WTD_STATEACTION_IGNORE,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = providerFlags,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                Marshal.StructureToPtr(trustData, pTrustData, false);

                pActionId = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                Marshal.StructureToPtr(WINTRUST_ACTION_GENERIC_VERIFY_V2, pActionId, false);

                int result = WinVerifyTrust(IntPtr.Zero, pActionId, pTrustData);
                return result == 0;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] WinVerifyTrust failed for {filePath}: {ex.Message}");
                return false;
            }
            finally
            {
                if (pFilePath != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pFilePath);
                }

                if (pFileInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pFileInfo);
                }

                if (pTrustData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTrustData);
                }

                if (pActionId != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pActionId);
                }
            }
        }

        private static string? GetPublisherNameFromFileVersion(string filePath)
        {
            try
            {
                var info = FileVersionInfo.GetVersionInfo(filePath);
                return string.IsNullOrEmpty(info.CompanyName) ? info.OriginalFilename : info.CompanyName;
            }
            catch
            {
                return null;
            }
        }
    }
}
