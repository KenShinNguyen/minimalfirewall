namespace MinimalFirewall;

internal sealed record PublisherCertificateIdentity(
    string Sha256Thumbprint,
    string Subject,
    string Issuer)
{
    internal string DisplayName =>
        SignatureValidationService.NormalizePublisherName(Subject) ?? Subject;

    internal string DisplayNameWithFingerprint =>
        $"{DisplayName} [SHA-256: {Sha256Thumbprint[..Math.Min(12, Sha256Thumbprint.Length)]}…]";
}

internal sealed record PublisherWhitelistEntry(
    string Sha256Thumbprint,
    string Subject,
    string Issuer,
    bool IsLegacy)
{
    internal string DisplayName
    {
        get
        {
            if (IsLegacy)
            {
                return $"[LEGACY INACTIVE] {Subject}";
            }

            string publisherName = SignatureValidationService.NormalizePublisherName(Subject) ?? Subject;
            string shortThumbprint = Sha256Thumbprint.Length > 12
                ? Sha256Thumbprint[..12]
                : Sha256Thumbprint;

            return $"{publisherName} [SHA-256: {shortThumbprint}…]";
        }
    }

    public override string ToString() => DisplayName;
}
