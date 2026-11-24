using Xunit;

namespace MinimalFirewall.Tests;

public sealed class PublisherWhitelistServiceBehaviorTests
{
    [Fact]
    public void Add_PersistsPublisherAndMatchingIsCaseInsensitiveAfterReload()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add("Acme Corporation");

        var reloaded = storage.CreateService();

        Assert.True(reloaded.IsTrusted("ACME CORPORATION"));
        Assert.Equal("Acme Corporation", Assert.Single(reloaded.GetTrustedPublishers()));
    }

    [Fact]
    public void Add_DuplicatePublisherWithDifferentCasing_IsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add("Acme Corporation");
        service.Add("ACME CORPORATION");

        Assert.Equal("Acme Corporation", Assert.Single(service.GetTrustedPublishers()));
    }

    [Fact]
    public void Remove_IsCaseInsensitiveAndPersistsDeletion()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();
        service.Add("Acme Corporation");

        service.Remove("ACME CORPORATION");

        var reloaded = storage.CreateService();
        Assert.False(reloaded.IsTrusted("Acme Corporation"));
        Assert.Empty(reloaded.GetTrustedPublishers());
    }

    [Fact]
    public void Load_NormalizesCertificateSubjectToCommonNameAndPersistsNormalizedValue()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, """["CN=Acme Corporation, O=Acme Ltd"]""");

        var service = storage.CreateService();

        Assert.True(service.IsTrusted("Acme Corporation"));
        Assert.Equal("Acme Corporation", Assert.Single(service.GetTrustedPublishers()));
        Assert.Contains("Acme Corporation", File.ReadAllText(storage.FilePath));
        Assert.DoesNotContain("CN=Acme Corporation", File.ReadAllText(storage.FilePath));
    }

    [Fact]
    public void Load_WhenJsonIsCorrupted_ReturnsEmptyWhitelistWithoutThrowing()
    {
        using var storage = new TemporaryPublisherStorage();
        File.WriteAllText(storage.FilePath, "{ invalid json");

        var service = storage.CreateService();

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(service.IsTrusted("Acme Corporation"));
    }

    [Fact]
    public void Add_EmptyPublisherIsIgnored()
    {
        using var storage = new TemporaryPublisherStorage();
        var service = storage.CreateService();

        service.Add(string.Empty);

        Assert.Empty(service.GetTrustedPublishers());
        Assert.False(File.Exists(storage.FilePath));
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
