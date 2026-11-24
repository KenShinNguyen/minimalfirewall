using System.Collections.Generic;
using System.Threading;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallSentryServiceBoundaryTests
{
    [Fact]
    public void BaselineScan_RoutesRuleEnumerationToObservationBackend()
    {
        var backend = new RecordingObservationBackend
        {
            ForeignRules =
            [
                CreateRule("Foreign Rule")
            ]
        };
        var sentry = new FirewallSentryService(backend);

        var changes = sentry.CheckForChanges();

        Assert.Single(changes);
        Assert.Equal("Foreign Rule", changes[0].Rule.Name);
        Assert.Equal(ChangeType.New, changes[0].Type);
        Assert.Equal(1, backend.GetForeignRulesCalls);
    }

    [Fact]
    public void IncrementalModifiedEvent_RoutesLookupToObservationBackend()
    {
        var backend = new RecordingObservationBackend
        {
            RuleByName =
            {
                ["Changed Rule"] = CreateRule("Changed Rule")
            }
        };
        var sentry = new FirewallSentryService(backend);

        sentry.CheckForChanges();

        InvokeChangeEvent(sentry, "Changed Rule", ChangeType.Modified);

        var changes = sentry.CheckForChanges();

        Assert.Single(changes);
        Assert.Equal("Changed Rule", changes[0].Rule.Name);
        Assert.Equal(ChangeType.Modified, changes[0].Type);
        Assert.Equal(["Changed Rule"], backend.Lookups);
    }

    [Fact]
    public void IncrementalDeletedEvent_DoesNotPerformRuleLookup()
    {
        var backend = new RecordingObservationBackend();
        var sentry = new FirewallSentryService(backend);

        sentry.CheckForChanges();
        InvokeChangeEvent(sentry, "Deleted Rule", ChangeType.Deleted);

        var changes = sentry.CheckForChanges();

        Assert.Single(changes);
        Assert.Equal(ChangeType.Deleted, changes[0].Type);
        Assert.Equal("Deleted Rule", changes[0].Rule.Name);
        Assert.Empty(backend.Lookups);
    }

    [Fact]
    public void MissingModifiedRule_IsDroppedWithoutThrowing()
    {
        var backend = new RecordingObservationBackend();
        var sentry = new FirewallSentryService(backend);

        sentry.CheckForChanges();
        InvokeChangeEvent(sentry, "Missing Rule", ChangeType.Modified);

        var changes = sentry.CheckForChanges();

        Assert.Empty(changes);
        Assert.Equal(["Missing Rule"], backend.Lookups);
    }

    [Fact]
    public void SentryDoesNotOwnFirewallRuleService()
    {
        var field = typeof(FirewallSentryService).GetField(
            "firewallService",
            System.Reflection.BindingFlags.Instance |
            System.Reflection.BindingFlags.NonPublic);

        Assert.Null(field);
    }

    private static AdvancedRuleViewModel CreateRule(string name) =>
        new()
        {
            Name = name,
            ApplicationName = @"C:\Apps\demo.exe",
            Grouping = "Foreign Group",
            Status = "Allow",
            Protocol = 6,
            ProtocolName = "TCP",
            IsEnabled = true
        };

    private static void InvokeChangeEvent(
        FirewallSentryService sentry,
        string ruleName,
        ChangeType type)
    {
        var pendingChangesField = typeof(FirewallSentryService).GetField(
            "_pendingChanges",
            System.Reflection.BindingFlags.Instance |
            System.Reflection.BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("_pendingChanges was not found.");

        var queue = (System.Collections.Concurrent.ConcurrentQueue<(string Name, ChangeType Type)>)pendingChangesField.GetValue(sentry)!;
        queue.Enqueue((ruleName, type));
    }

    private sealed class RecordingObservationBackend : IFirewallRuleObservationBackend
    {
        public Dictionary<string, AdvancedRuleViewModel> RuleByName { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public List<AdvancedRuleViewModel> ForeignRules { get; init; } = [];
        public List<string> Lookups { get; } = [];
        public int GetForeignRulesCalls { get; private set; }

        public AdvancedRuleViewModel? GetRuleByName(string ruleName)
        {
            Lookups.Add(ruleName);
            return RuleByName.TryGetValue(ruleName, out var rule) ? rule : null;
        }

        public List<AdvancedRuleViewModel> GetForeignRules(
            IProgress<int>? progress = null,
            CancellationToken token = default)
        {
            GetForeignRulesCalls++;
            progress?.Report(100);
            return [.. ForeignRules];
        }
    }
}
