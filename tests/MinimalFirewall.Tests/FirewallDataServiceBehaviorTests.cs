using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallDataServiceBehaviorTests
{
    [Fact]
    public async Task GetMfwRulesAsync_MapsSnapshotAndCachesSuccessfulRead()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(DemoSnapshot());

        var service = new FirewallDataService(null!, null!, storage.CreateService(), backend);

        var first = await service.GetMfwRulesAsync(CancellationToken.None);
        var second = await service.GetMfwRulesAsync(CancellationToken.None);

        var mapped = Assert.Single(first);
        Assert.Equal("Demo Rule", mapped.Name);
        Assert.Equal("Block", mapped.Status);
        Assert.Equal(Directions.Outgoing, mapped.Direction);
        Assert.Equal("TCP", mapped.ProtocolName);
        Assert.Equal(@"C:\Apps\demo.exe", mapped.ApplicationName);
        Assert.Equal("443", mapped.LocalPorts);
        Assert.Equal("203.0.113.10", mapped.RemoteAddresses);
        Assert.Equal("Demo Group - MFW", mapped.Grouping);
        Assert.Single(second);
        Assert.Equal(1, backend.SnapshotQueryCalls);
    }

    [Fact]
    public async Task GetMfwRulesAsync_SuccessfulEmptyRead_IsCachedAsEmpty()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend();
        var service = new FirewallDataService(null!, null!, storage.CreateService(), backend);

        var first = await service.GetMfwRulesAsync(CancellationToken.None);
        var second = await service.GetMfwRulesAsync(CancellationToken.None);

        Assert.Empty(first);
        Assert.Empty(second);
        Assert.Equal(1, backend.SnapshotQueryCalls);
    }

    [Fact]
    public async Task GetMfwRulesAsync_ThrownQueryFailure_IsPropagatedAndRetried()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend { ThrowOnQuery = true };
        backend.Seed(DemoSnapshot());
        var service = new FirewallDataService(null!, null!, storage.CreateService(), backend);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.GetMfwRulesAsync(CancellationToken.None));

        backend.ThrowOnQuery = false;
        var recovered = await service.GetMfwRulesAsync(CancellationToken.None);

        Assert.Single(recovered);
        Assert.Equal(2, backend.SnapshotQueryCalls);
    }

    private static FirewallRuleSnapshot DemoSnapshot() => new(
        "Demo Rule",
        "Demo description",
        true,
        (int)Directions.Outgoing,
        false,
        6,
        @"C:\Apps\demo.exe",
        string.Empty,
        "443",
        "*",
        "*",
        "203.0.113.10",
        0x7FFFFFFF,
        "Demo Group - MFW",
        "All",
        string.Empty);

    private sealed class TemporaryRuleTimestampStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), $"mfw-tests-{Guid.NewGuid():N}");

        public RuleTimestampService CreateService()
        {
            Directory.CreateDirectory(_directory);
            return new RuleTimestampService(Path.Combine(_directory, "timestamps.json"));
        }

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
