using System.Security.Cryptography.X509Certificates;

namespace MinimalFirewall;

public sealed record PublisherIdentity(
    string CommonName,
    string Organization,
    string Country)
{
    public const string V2Prefix = "v2|";

    private const string OidCommonName = "2.5.4.3";
    private const string OidOrganization = "2.5.4.10";
    private const string OidCountry = "2.5.4.6";

    public static PublisherIdentity FromCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return FromSubjectName(certificate.SubjectName);
    }

    public static PublisherIdentity FromSubjectName(X500DistinguishedName subjectName)
    {
        ArgumentNullException.ThrowIfNull(subjectName);

        string cn = string.Empty;
        string organization = string.Empty;
        string country = string.Empty;

        foreach (X500RelativeDistinguishedName rdn in subjectName.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.HasMultipleElements)
            {
                continue;
            }

            string? oid = rdn.GetSingleElementType()?.Value;
            string value = NormalizeComponent(rdn.GetSingleElementValue());

            switch (oid)
            {
                case OidCommonName when string.IsNullOrEmpty(cn):
                    cn = value;
                    break;
                case OidOrganization when string.IsNullOrEmpty(organization):
                    organization = value;
                    break;
                case OidCountry when string.IsNullOrEmpty(country):
                    country = value;
                    break;
            }
        }

        return new PublisherIdentity(cn, organization, country);
    }

    public string ToCanonicalV2Key() =>
        $"{V2Prefix}CN={Escape(CommonName)}|O={Escape(Organization)}|C={Escape(Country)}";

    public static bool IsV2Key(string? storedEntry) =>
        !string.IsNullOrWhiteSpace(storedEntry)
        && storedEntry.StartsWith(V2Prefix, StringComparison.OrdinalIgnoreCase);

    public static string NormalizeLegacyCn(string? rawName) =>
        NormalizeComponent(rawName);

    private static string NormalizeComponent(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        return string.Join(' ', input.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }

    private static string Escape(string value) =>
        value.Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("|", @"\|", StringComparison.Ordinal);
}

public enum PublisherTrustMatchKind
{
    NoMatch = 0,
    ExactV2Match = 1,
    LegacyCnMatch = 2
}

public sealed record PublisherTrustMatchResult(
    PublisherTrustMatchKind MatchKind,
    string? MatchedEntry)
{
    public bool IsTrusted =>
        MatchKind is PublisherTrustMatchKind.ExactV2Match or PublisherTrustMatchKind.LegacyCnMatch;
}

public static class PublisherTrustMatcher
{
    public static PublisherTrustMatchResult Evaluate(
        PublisherIdentity candidate,
        IEnumerable<string> trustedEntries,
        bool allowLegacyCnFallback = true)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(trustedEntries);

        if (string.IsNullOrEmpty(candidate.CommonName))
        {
            return new PublisherTrustMatchResult(PublisherTrustMatchKind.NoMatch, null);
        }

        string candidateV2Key = candidate.ToCanonicalV2Key();
        string? legacyMatch = null;

        foreach (string rawEntry in trustedEntries)
        {
            if (string.IsNullOrWhiteSpace(rawEntry))
            {
                continue;
            }

            if (PublisherIdentity.IsV2Key(rawEntry))
            {
                if (string.Equals(rawEntry.Trim(), candidateV2Key, StringComparison.OrdinalIgnoreCase))
                {
                    return new PublisherTrustMatchResult(PublisherTrustMatchKind.ExactV2Match, rawEntry);
                }
            }
            else if (allowLegacyCnFallback && legacyMatch is null)
            {
                string normalizedLegacy = PublisherIdentity.NormalizeLegacyCn(rawEntry);
                if (string.Equals(normalizedLegacy, candidate.CommonName, StringComparison.OrdinalIgnoreCase))
                {
                    legacyMatch = rawEntry;
                }
            }
        }

        return legacyMatch is not null
            ? new PublisherTrustMatchResult(PublisherTrustMatchKind.LegacyCnMatch, legacyMatch)
            : new PublisherTrustMatchResult(PublisherTrustMatchKind.NoMatch, null);
    }
}
