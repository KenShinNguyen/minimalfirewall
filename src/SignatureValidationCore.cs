using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace MinimalFirewall;

internal interface IWinTrustVerifier
{
    bool Verify(string filePath, uint revocationChecks, uint providerFlags);
}

internal sealed class SignatureValidationCore
{
    private readonly IWinTrustVerifier _verifier;
    private readonly Func<string, PublisherSignerIdentity?> _signerResolver;

    internal SignatureValidationCore(
        IWinTrustVerifier verifier,
        Func<string, PublisherSignerIdentity?> signerResolver)
    {
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _signerResolver = signerResolver ?? throw new ArgumentNullException(nameof(signerResolver));
    }

    internal PublisherSignerIdentity? ValidateSigner(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return null;
        }

        if (!_verifier.Verify(filePath, revocationChecks: 1u, providerFlags: 0x40u))
        {
            return null;
        }

        return _signerResolver(filePath);
    }

    internal bool IsSignatureTrusted(
        string filePath,
        IEnumerable<string> trustedEntries,
        bool allowLegacyCnFallback,
        out PublisherTrustMatchResult match)
    {
        match = new PublisherTrustMatchResult(PublisherTrustMatchKind.NoMatch, null);
        PublisherSignerIdentity? signer = ValidateSigner(filePath);
        if (signer is null)
        {
            return false;
        }

        PublisherIdentity candidate = PublisherIdentity.FromSubjectName(
            new X500DistinguishedName(signer.Subject));

        match = PublisherTrustMatcher.Evaluate(candidate, trustedEntries, allowLegacyCnFallback);
        return match.IsTrusted;
    }
}

internal sealed class WindowsWinTrustVerifier : IWinTrustVerifier
{
    public bool Verify(string filePath, uint revocationChecks, uint providerFlags)
        => SignatureValidationService.VerifyWithWinTrustForSeam(
            filePath,
            revocationChecks,
            providerFlags);
}
