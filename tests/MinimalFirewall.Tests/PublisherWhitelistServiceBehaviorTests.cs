using Xunit;

namespace MinimalFirewall.Tests;

public sealed class PublisherWhitelistServiceBehaviorTests
{
    private const string ThumbprintA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string ThumbprintB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [Fact]
    public void Add_PersistsCertificateIdentityAndMatchingIsCaseInsensitiveAfterReload()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add(ThumbprintA, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd, C=US");

        var reloaded = storage.CreateService();

        Assert.True(reloaded.IsTrusted(ThumbprintA.ToLowerInvariant()));
        var entry = Assert.Single(reloaded.GetTrustedPublishers());
        Assert.Equal("Acme Corporation", entry.DisplayName);
        Assert.Equal(ThumbprintA, entry.Sha256Thumbprint);
        Assert.False(entry.IsLegacy);
    }

    [Fact]
    public void SameDisplayNameWithDifferentCertificateFingerprints_RemainsIsolated()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add(ThumbprintA, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");
        service.Add(ThumbprintB, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");

        Assert.True(service.IsTrusted(ThumbprintA));
        Assert.True(service.IsTrusted(ThumbprintB));
        Assert.Equal(2, service.GetTrustedPublishers().Count);
    }

    [Fact]
    public void Add_DuplicateFingerprintWithDifferentCasing_IsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add(ThumbprintA, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");
        service.Add(ThumbprintA.ToLowerInvariant(), "ACME CORPORATION", "CN=Acme Corporation, O=Acme Ltd");

        Assert.Equal("Acme Corporation", Assert.Single(service.GetTrustedPublishers()).DisplayName);
    }

    [Fact]
    public void Remove_RemovesOnlySelectedCertificateAndPersistsDeletion()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        service.Add(ThumbprintA, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");
        service.Add(ThumbprintB, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");

        TrustedPublisherEntry selected = service.GetTrustedPublishers()
            .Single(entry => entry.Sha256Thumbprint == ThumbprintA);
        service.Remove(selected);

        var reloaded = storage.CreateService();
        Assert.False(reloaded.IsTrusted(ThumbprintA));
        Assert.True(reloaded.IsTrusted(ThumbprintB));
        Assert.Single(reloaded.GetTrustedPublishers());
    }

    [Fact]
    public void Load_LegacyNameOnlyEntriesRemainVisibleButAreNeverTrusted()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, """["Acme Corporation","CN=Contoso, O=Contoso Ltd"]""");

        var service = storage.CreateService();

        Assert.False(service.IsTrusted(ThumbprintA));
        var legacy = Assert.Single(service.GetTrustedPublishers().Where(entry => entry.IsLegacy));
        Assert.Equal("Contoso", legacy.DisplayName);
        Assert.Contains("disabled", legacy.ToString(), StringComparison.OrdinalIgnoreCase);

        service.Remove(legacy);
        Assert.Single(service.GetTrustedPublishers());
        Assert.Contains("Acme Corporation", service.GetTrustedPublishers().Single().DisplayName);
    }

    [Fact]
    public void Add_InvalidThumbprintOrEmptyMetadata_IsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add("Acme Corporation", "Acme Corporation", "CN=Acme Corporation");
        service.Add(ThumbprintA, string.Empty, "CN=Acme Corporation");
        service.Add(ThumbprintA, "Acme Corporation", string.Empty);

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(File.Exists(storage.FilePath));
    }

    [Fact]
    public void Load_WhenJsonIsCorrupted_ReturnsEmptyWhitelistWithoutThrowing()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, "{ invalid json");

        var service = storage.CreateService();

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(service.IsTrusted(ThumbprintA));
    }

    [Fact]
    public void Remove_LegacyEntryDoesNotRemoveCertificateWithSameDisplayName()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, """["Acme Corporation"]""");
        var service = storage.CreateService();
        service.Add(ThumbprintA, "Acme Corporation", "CN=Acme Corporation, O=Acme Ltd");

        TrustedPublisherEntry legacy = Assert.Single(service.GetTrustedPublishers().Where(entry => entry.IsLegacy));
        service.Remove(legacy);

        Assert.True(service.IsTrusted(ThumbprintA));
        Assert.Single(service.GetTrustedPublishers());
    }

    private sealed class TemporaryPublisherStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-publisher-tests-{Guid.NewGuid():N}");

        public string FilePath => Path.Combine(_directory, "trusted_publishers.json");

        public TemporaryPublisherStorage()
        {
            Directory.CreateDirectory(_directory);
        }

        public PublisherWhitelistService CreateService() => new(FilePath);

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
