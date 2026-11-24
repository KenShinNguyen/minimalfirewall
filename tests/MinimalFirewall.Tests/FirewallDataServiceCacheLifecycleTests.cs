using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallDataServiceCacheLifecycleTests
{
    [Fact]
    public async Task GetAggregatedRulesAsync_GroupsSnapshotsAndCachesTheAggregate()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(
            DemoSnapshot(
                "Demo Rule - Inbound Allow",
                Directions.Incoming,
                isAllow: true,
                localPorts: "443"),
            DemoSnapshot(
                "Demo Rule - Inbound Block",
                Directions.Incoming,
                isAllow: false,
                localPorts: "443"),
            DemoSnapshot(
                "Demo Rule - Outbound Allow",
                Directions.Outgoing,
                isAllow: true,
                localPorts: "80"));

        var service = CreateService(backend, storage);
        var firstProgress = new RecordingProgress();
        var secondProgress = new RecordingProgress();

        var first = await service.GetAggregatedRulesAsync(
            CancellationToken.None,
            firstProgress);
        var second = await service.GetAggregatedRulesAsync(
            CancellationToken.None,
            secondProgress);

        var aggregate = Assert.Single(first);
        Assert.Same(first, second);
        Assert.Equal(1, backend.SnapshotQueryCalls);
        Assert.Equal("Demo Rule", aggregate.Name);
        Assert.Equal("Allow, Block", aggregate.InboundStatus);
        Assert.Equal("Allow", aggregate.OutboundStatus);
        Assert.Equal("443, 80", aggregate.LocalPorts);
        Assert.Equal(3, aggregate.UnderlyingRules.Count);
        Assert.Equal(new[] { 100 }, secondProgress.Values);
        Assert.Contains(100, firstProgress.Values);
    }

    [Fact]
    public async Task ClearAggregatedRulesCache_RebuildsAggregateAndKeepsSnapshotCache()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(DemoSnapshot("Demo Rule", Directions.Outgoing, isAllow: false));
        var service = CreateService(backend, storage);

        var first = await service.GetAggregatedRulesAsync(CancellationToken.None);
        service.ClearAggregatedRulesCache();
        var second = await service.GetAggregatedRulesAsync(CancellationToken.None);

        Assert.NotSame(first, second);
        Assert.Same(first[0].UnderlyingRules[0], second[0].UnderlyingRules[0]);
        Assert.Equal(1, backend.SnapshotQueryCalls);
    }

    [Fact]
    public async Task InvalidateRuleCache_RefreshesSnapshotAndAggregateCaches()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(DemoSnapshot("First Rule", Directions.Outgoing, isAllow: true));
        var service = CreateService(backend, storage);

        var first = await service.GetAggregatedRulesAsync(CancellationToken.None);
        Assert.Single(first);

        backend.Seed(
            DemoSnapshot(
                "Second Rule",
                Directions.Incoming,
                isAllow: false,
                grouping: "Second Group - MFW",
                applicationName: @"C:\Apps\second.exe"));

        service.InvalidateRuleCache();

        var refreshed = await service.GetAggregatedRulesAsync(CancellationToken.None);

        Assert.Equal(2, refreshed.Count);
        Assert.Contains(refreshed, rule => rule.Name == "First Rule");
        Assert.Contains(refreshed, rule => rule.Name == "Second Rule");
        Assert.Equal(2, backend.SnapshotQueryCalls);
    }

    [Fact]
    public async Task FailedStructuredQuery_IsNotCachedAndSuccessfulRetryIsCached()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        var backend = new SequenceQueryBackend(
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Failure(
                "temporary query failure"),
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Success(
                new[] { DemoSnapshot("Recovered Rule", Directions.Outgoing, isAllow: true) }));
        var service = CreateService(backend, storage);

        var failedAttempt = await service.GetMfwRulesAsync(CancellationToken.None);
        var recovered = await service.GetMfwRulesAsync(CancellationToken.None);
        var cached = await service.GetMfwRulesAsync(CancellationToken.None);

        Assert.Empty(failedAttempt);
        Assert.Equal("Recovered Rule", Assert.Single(recovered).Name);
        Assert.Same(recovered, cached);
        Assert.Equal(2, backend.SnapshotQueryCalls);
    }

    [Fact]
    public async Task CancelledInFlightQuery_IsNotCachedAndCanBeRetried()
    {
        using var storage = new TemporaryRuleTimestampStorage();
        using var backend = new BlockingQueryBackend(
            DemoSnapshot("Recovered Rule", Directions.Outgoing, isAllow: true));
        var service = CreateService(backend, storage);
        using var cancellation = new CancellationTokenSource();

        var cancelledRead = service.GetMfwRulesAsync(cancellation.Token);
        await backend.QueryStarted.Task;
        cancellation.Cancel();
        backend.ReleaseQuery.Set();

        var cancelledResult = await cancelledRead;

        backend.BlockQuery = false;
        var recovered = await service.GetMfwRulesAsync(CancellationToken.None);

        Assert.Empty(cancelledResult);
        Assert.Equal("Recovered Rule", Assert.Single(recovered).Name);
        Assert.Equal(2, backend.SnapshotQueryCalls);
    }

    private static FirewallDataService CreateService(
        IFirewallRuleQueryBackend backend,
        TemporaryRuleTimestampStorage storage) =>
        new(null!, null!, storage.CreateService(), backend);

    private static FirewallRuleSnapshot DemoSnapshot(
        string name,
        Directions direction,
        bool isAllow,
        string localPorts = "*",
        string grouping = "Demo Group - MFW",
        string applicationName = @"C:\Apps\demo.exe") =>
        new(
            name,
            "Demo description",
            true,
            (int)direction,
            isAllow,
            6,
            applicationName,
            string.Empty,
            localPorts,
            "*",
            "*",
            "203.0.113.10",
            0x7FFFFFFF,
            grouping,
            "All",
            string.Empty);

    private sealed class RecordingProgress : IProgress<int>
    {
        public List<int> Values { get; } = [];

        public void Report(int value) => Values.Add(value);
    }

    private sealed class TemporaryRuleTimestampStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-tests-{Guid.NewGuid():N}");

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

    private sealed class SequenceQueryBackend : IFirewallRuleQueryBackend
    {
        private readonly Queue<FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>> _results;

        public SequenceQueryBackend(
            params FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>[] results)
        {
            _results = new Queue<FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>>(results);
        }

        public int SnapshotQueryCalls { get; private set; }

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
        {
            SnapshotQueryCalls++;
            return _results.Count > 0
                ? _results.Dequeue()
                : FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Failure(
                    "No test query result configured.");
        }

        public FirewallRuleQueryResult<IReadOnlyList<string>> GetRuleNamesByPathAndDirection(
            string appPath,
            Directions direction) =>
            FirewallRuleQueryResult<IReadOnlyList<string>>.Success([]);

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules() =>
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success([]);

        public FirewallRuleQueryResult<int> EnableMfwRules() =>
            FirewallRuleQueryResult<int>.Success(0);

        public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled) =>
            FirewallRuleQueryResult<int>.Success(0);
    }

    private sealed class BlockingQueryBackend : IFirewallRuleQueryBackend, IDisposable
    {
        private readonly IReadOnlyList<FirewallRuleSnapshot> _snapshots;

        public BlockingQueryBackend(params FirewallRuleSnapshot[] snapshots)
        {
            _snapshots = snapshots;
        }

        public TaskCompletionSource<bool> QueryStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ManualResetEventSlim ReleaseQuery { get; } = new(false);
        public bool BlockQuery { get; set; } = true;
        public int SnapshotQueryCalls { get; private set; }

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
        {
            SnapshotQueryCalls++;
            QueryStarted.TrySetResult(true);

            if (BlockQuery && !ReleaseQuery.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("The test did not release the blocked query.");
            }

            return FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Success(_snapshots);
        }

        public FirewallRuleQueryResult<IReadOnlyList<string>> GetRuleNamesByPathAndDirection(
            string appPath,
            Directions direction) =>
            FirewallRuleQueryResult<IReadOnlyList<string>>.Success([]);

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules() =>
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success([]);

        public FirewallRuleQueryResult<int> EnableMfwRules() =>
            FirewallRuleQueryResult<int>.Success(0);

        public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled) =>
            FirewallRuleQueryResult<int>.Success(0);

        public void Dispose() => ReleaseQuery.Dispose();
    }
}
