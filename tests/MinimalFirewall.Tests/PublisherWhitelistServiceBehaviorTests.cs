using Xunit;

namespace MinimalFirewall.Tests;

public sealed class PublisherWhitelistServiceBehaviorTests
{
    [Fact]
    public void Add_PersistsCertificateFingerprintAndMatchingIsCaseInsensitiveAfterReload()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        var identity = CreateIdentity(thumbprint: new string('A', 64));

        service.Add(identity);

        var reloaded = storage.CreateService();

        Assert.True(reloaded.IsTrusted(identity with { Sha256Thumbprint = identity.Sha256Thumbprint.ToLowerInvariant() }));
        var savedEntry = Assert.Single(reloaded.GetTrustedPublishers());
        Assert.False(savedEntry.IsLegacy);
        Assert.Equal(identity.Subject, savedEntry.Subject);
        Assert.Equal(identity.Issuer, savedEntry.Issuer);
        Assert.Contains(identity.Sha256Thumbprint, File.ReadAllText(storage.FilePath));
    }

    [Fact]
    public void Add_DuplicateFingerprintWithDifferentCasing_IsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        var identity = CreateIdentity(thumbprint: new string('B', 64));

        service.Add(identity);
        service.Add(identity with { Sha256Thumbprint = identity.Sha256Thumbprint.ToLowerInvariant() });

        var saved = Assert.Single(service.GetTrustedPublishers());
        Assert.Equal(identity.Subject, saved.Subject);
        Assert.Equal(identity.Sha256Thumbprint, saved.Sha256Thumbprint);
    }

    [Fact]
    public void IsTrusted_DoesNotConflateDifferentCertificatesWithTheSameCommonName()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        var trusted = CreateIdentity(
            thumbprint: new string('C', 64),
            subject: "CN=Acme Corporation, O=Acme One Ltd");
        var other = CreateIdentity(
            thumbprint: new string('D', 64),
            subject: "CN=Acme Corporation, O=Acme Two Ltd");

        service.Add(trusted);

        Assert.True(service.IsTrusted(trusted));
        Assert.False(service.IsTrusted(other));
    }

    [Fact]
    public void Remove_IsCaseInsensitiveAndPersistsCertificateDeletion()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        var identity = CreateIdentity(thumbprint: new string('E', 64));
        service.Add(identity);

        service.Remove(Assert.Single(service.GetTrustedPublishers()));

        var reloaded = storage.CreateService();
        Assert.False(reloaded.IsTrusted(identity));
        Assert.Empty(reloaded.GetTrustedPublishers());
    }

    [Fact]
    public void Load_LegacyCommonNameEntriesArePreservedButNeverTrusted()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, """["CN=Acme Corporation, O=Acme Ltd"]""");

        var service = storage.CreateService();
        var unrelatedCertificate = CreateIdentity(
            thumbprint: new string('F', 64),
            subject: "CN=Acme Corporation, O=Acme Ltd");

        Assert.False(service.IsTrusted(unrelatedCertificate));

        var legacyEntry = Assert.Single(service.GetTrustedPublishers());
        Assert.True(legacyEntry.IsLegacy);
        Assert.Contains("LEGACY INACTIVE", legacyEntry.DisplayName);
        Assert.Contains("\"Version\": 2", File.ReadAllText(storage.FilePath));
        Assert.Contains("CN=Acme Corporation, O=Acme Ltd", File.ReadAllText(storage.FilePath));
    }

    [Fact]
    public void Remove_CanDeleteLegacyInactiveEntry()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, """["Acme Corporation"]""");

        var service = storage.CreateService();
        service.Remove(Assert.Single(service.GetTrustedPublishers()));

        var reloaded = storage.CreateService();
        Assert.Empty(reloaded.GetTrustedPublishers());
        Assert.DoesNotContain("LegacyNames", File.ReadAllText(storage.FilePath));
    }

    [Fact]
    public void Load_WhenJsonIsCorrupted_ReturnsEmptyWhitelistWithoutThrowing()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, "{ invalid json");

        var service = storage.CreateService();

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(service.IsTrusted(CreateIdentity(thumbprint: new string('1', 64))));
    }

    [Fact]
    public void Add_InvalidOrNonSha256Fingerprint_IsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add(CreateIdentity(thumbprint: "not-a-thumbprint"));

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(File.Exists(storage.FilePath));
    }

    private static PublisherCertificateIdentity CreateIdentity(
        string thumbprint,
        string subject = "CN=Acme Corporation, O=Acme Ltd",
        string issuer = "CN=Acme Code Signing CA, O=Acme Trust")
        => new(thumbprint, subject, issuer);

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
