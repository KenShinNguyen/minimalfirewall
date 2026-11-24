using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class SignatureValidationServiceTests
{
    [Fact]
    public void Validate_WhenFileDoesNotExist_ReturnsNotTrustedWithoutCallingWinTrust()
    {
        var verifier = new FakeWinTrustVerifier();
        var core = new SignatureValidationCore(verifier, _ => null);

        bool trusted = core.IsSignatureTrusted(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe"),
            [],
            allowLegacyCnFallback: true,
            out _);

        Assert.False(trusted);
        Assert.Equal(0, verifier.Calls);
    }

    [Fact]
    public void Validate_PassesWholeChainRevocationAndChainFlagsToWinTrustVerifier()
    {
        string file = CreateTempFile();
        try
        {
            var verifier = new FakeWinTrustVerifier { Result = true };
            var core = new SignatureValidationCore(
                verifier,
                _ => new PublisherSignerIdentity(
                    "Contoso, Inc.",
                    "CN=Contoso\\, Inc., O=Contoso Ltd., C=US",
                    "ABC"));

            bool trusted = core.IsSignatureTrusted(
                file,
                ["v2|CN=Contoso, Inc.|O=Contoso Ltd.|C=US"],
                allowLegacyCnFallback: false,
                out var match);

            Assert.True(trusted);
            Assert.Equal(PublisherTrustMatchKind.ExactV2Match, match.MatchKind);
            Assert.Equal(1u, verifier.RevocationChecks);
            Assert.Equal(0x40u, verifier.ProviderFlags);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Validate_WhenWinTrustReportsRevokedChain_RejectsEvenIfPublisherIsTrusted()
    {
        string file = CreateTempFile();
        try
        {
            var verifier = new FakeWinTrustVerifier { Result = false };
            var core = new SignatureValidationCore(
                verifier,
                _ => new PublisherSignerIdentity(
                    "Contoso",
                    "CN=Contoso, O=Contoso Ltd., C=US",
                    "ABC"));

            bool trusted = core.IsSignatureTrusted(
                file,
                ["v2|CN=Contoso|O=Contoso Ltd.|C=US"],
                allowLegacyCnFallback: false,
                out _);

            Assert.False(trusted);
            Assert.Equal(1, verifier.Calls);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Validate_SameCnDifferentOrganization_IsRejectedUnderV2()
    {
        string file = CreateTempFile();
        try
        {
            var core = new SignatureValidationCore(
                new FakeWinTrustVerifier { Result = true },
                _ => new PublisherSignerIdentity(
                    "Contoso",
                    "CN=Contoso, O=Other Corp, C=US",
                    "ABC"));

            bool trusted = core.IsSignatureTrusted(
                file,
                ["v2|CN=Contoso|O=Contoso Ltd.|C=US"],
                allowLegacyCnFallback: false,
                out var match);

            Assert.False(trusted);
            Assert.Equal(PublisherTrustMatchKind.NoMatch, match.MatchKind);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Validate_LegacyCnFallback_AllowsWhenEnabled()
    {
        string file = CreateTempFile();
        try
        {
            var core = new SignatureValidationCore(
                new FakeWinTrustVerifier { Result = true },
                _ => new PublisherSignerIdentity(
                    "Contoso",
                    "CN=Contoso, O=Other Corp, C=US",
                    "ABC"));

            bool trusted = core.IsSignatureTrusted(
                file,
                ["Contoso"],
                allowLegacyCnFallback: true,
                out var match);

            Assert.True(trusted);
            Assert.Equal(PublisherTrustMatchKind.LegacyCnMatch, match.MatchKind);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Validate_LegacyCnFallback_RejectsWhenStrictV2Enabled()
    {
        string file = CreateTempFile();
        try
        {
            var core = new SignatureValidationCore(
                new FakeWinTrustVerifier { Result = true },
                _ => new PublisherSignerIdentity(
                    "Contoso",
                    "CN=Contoso, O=Other Corp, C=US",
                    "ABC"));

            bool trusted = core.IsSignatureTrusted(
                file,
                ["Contoso"],
                allowLegacyCnFallback: false,
                out var match);

            Assert.False(trusted);
            Assert.Equal(PublisherTrustMatchKind.NoMatch, match.MatchKind);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static string CreateTempFile()
    {
        string path = Path.Combine(Path.GetTempPath(), $"mfw-signature-{Guid.NewGuid():N}.exe");
        File.WriteAllText(path, "not a real PE");
        return path;
    }

    private sealed class FakeWinTrustVerifier : IWinTrustVerifier
    {
        public bool Result { get; set; }
        public int Calls { get; private set; }
        public uint RevocationChecks { get; private set; }
        public uint ProviderFlags { get; private set; }

        public bool Verify(string filePath, uint revocationChecks, uint providerFlags)
        {
            Calls++;
            RevocationChecks = revocationChecks;
            ProviderFlags = providerFlags;
            return Result;
        }
    }
}
