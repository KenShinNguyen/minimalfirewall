using Xunit;
using MinimalFirewall.TypedObjects;

namespace MinimalFirewall.Tests;

public sealed class FirewallDataServiceCacheContractTests
{
    [Fact]
    public async Task GetMfwRulesAsync_FailedSnapshotQuery_IsNotCachedAndRetried()
    {
        var backend = new SequenceQueryBackend(
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Failure("temporary firewall query failure"),
            FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Failure("temporary firewall query failure"));
        var service = new FirewallDataService(null!, null!, null!, backend);

        var firstAttempt = await service.GetMfwRulesAsync(CancellationToken.None);
        var secondAttempt = await service.GetMfwRulesAsync(CancellationToken.None);

        Assert.Empty(firstAttempt);
        Assert.Empty(secondAttempt);
        Assert.Equal(2, backend.SnapshotCalls);
    }

    private sealed class SequenceQueryBackend : IFirewallRuleQueryBackend
    {
        private readonly Queue<FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>> _results;

        public SequenceQueryBackend(params FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>[] results)
        {
            _results = new Queue<FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>>(results);
        }

        public int SnapshotCalls { get; private set; }

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
        {
            SnapshotCalls++;
            return _results.Count > 0
                ? _results.Dequeue()
                : FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Failure("No test result configured.");
        }

        public FirewallRuleQueryResult<IReadOnlyList<string>> GetRuleNamesByPathAndDirection(
            string appPath,
            Directions direction)
            => FirewallRuleQueryResult<IReadOnlyList<string>>.Success([]);

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules()
            => FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success([]);

        public FirewallRuleQueryResult<int> EnableMfwRules()
            => FirewallRuleQueryResult<int>.Success(0);

        public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled)
            => FirewallRuleQueryResult<int>.Success(0);
    }
}
