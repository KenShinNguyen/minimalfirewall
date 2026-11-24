using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class PublisherIdentityTests
{
    [Fact]
    public void FromSubjectName_WithEscapedCommasAndQuotes_ExtractsCnOrgCountryAccurately()
    {
        var subject = new X500DistinguishedName(
            "CN=Contoso\\, Inc., O=Contoso\\, Ltd., C=US",
            X500DistinguishedNameFlags.None);

        PublisherIdentity identity = PublisherIdentity.FromSubjectName(subject);

        Assert.Equal("Contoso, Inc.", identity.CommonName);
        Assert.Equal("Contoso, Ltd.", identity.Organization);
        Assert.Equal("US", identity.Country);
    }

    [Fact]
    public void Evaluate_WhenSameCnButDifferentOrganization_RejectsV2Entry()
    {
        var candidate = new PublisherIdentity("Contoso", "Contoso Ltd", "US");
        var trusted = new[] { new PublisherIdentity("Contoso", "Other Corp", "US").ToCanonicalV2Key() };

        PublisherTrustMatchResult result = PublisherTrustMatcher.Evaluate(candidate, trusted);

        Assert.Equal(PublisherTrustMatchKind.NoMatch, result.MatchKind);
    }

    [Fact]
    public void Evaluate_WhenLegacyCnEntryExists_ReturnsLegacyCnMatch_WhenFallbackEnabled()
    {
        var candidate = new PublisherIdentity("Contoso", "Contoso Ltd", "US");

        PublisherTrustMatchResult result = PublisherTrustMatcher.Evaluate(
            candidate,
            ["Contoso"],
            allowLegacyCnFallback: true);

        Assert.Equal(PublisherTrustMatchKind.LegacyCnMatch, result.MatchKind);
    }

    [Fact]
    public void Evaluate_WhenLegacyFallbackDisabled_RejectsLegacyCnEntry()
    {
        var candidate = new PublisherIdentity("Contoso", "Contoso Ltd", "US");

        PublisherTrustMatchResult result = PublisherTrustMatcher.Evaluate(
            candidate,
            ["Contoso"],
            allowLegacyCnFallback: false);

        Assert.Equal(PublisherTrustMatchKind.NoMatch, result.MatchKind);
    }

    [Fact]
    public void Evaluate_WhenBothV2AndLegacyExist_PrefersExactV2Match()
    {
        var candidate = new PublisherIdentity("Contoso", "Contoso Ltd", "US");
        string v2 = candidate.ToCanonicalV2Key();

        PublisherTrustMatchResult result = PublisherTrustMatcher.Evaluate(
            candidate,
            ["Contoso", v2],
            allowLegacyCnFallback: true);

        Assert.Equal(PublisherTrustMatchKind.ExactV2Match, result.MatchKind);
        Assert.Equal(v2, result.MatchedEntry);
    }

    [Fact]
    public void V2Key_PreservesEmptyOrganizationAndCountryAsExplicitFields()
    {
        var identity = new PublisherIdentity("Contoso", string.Empty, string.Empty);

        Assert.Equal("v2|CN=Contoso|O=|C=", identity.ToCanonicalV2Key());
    }
}
