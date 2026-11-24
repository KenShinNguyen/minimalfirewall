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
            public IntPtr pUnion;       // Union of pFile/pCatalog/pBlob — one IntPtr
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

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_WHOLECHAIN = 1;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_STATEACTION_IGNORE = 0;
        private const int WTD_REVOCATION_CHECK_CHAIN = 0x40;

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


