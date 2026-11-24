using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallActionsServiceBehaviorTests
{
    [Fact]
    public void DeleteAdvancedRules_RemovesMatchingRulesFromInMemoryBackend()
    {
        var backend = new InMemoryFirewallBackend();
        backend.Seed(
            Snapshot("Rule A"),
            Snapshot("Rule B"));

        using var service = CreateService(backend);

        service.DeleteAdvancedRules(["Rule A"]);

        Assert.Equal(["Rule B"], backend.Rules.Select(rule => rule.Name));
        Assert.Contains("DeleteByName", backend.Operations);
    }

    [Fact]
    public void DeleteAdvancedRules_WhenBackendReturnsFailure_PreservesBackendState()
    {
        var backend = new InMemoryFirewallBackend { FailMutations = true };
        backend.Seed(Snapshot("Rule A"));

        using var service = CreateService(backend);

        service.DeleteAdvancedRules(["Rule A"]);

        Assert.Equal("Rule A", Assert.Single(backend.Rules).Name);
    }

    [Fact]
    public void DeleteAdvancedRules_WhenBackendThrows_PreservesStateAndPropagatesFailure()
    {
        var backend = new InMemoryFirewallBackend { ThrowOnMutate = true };
        backend.Seed(Snapshot("Rule A"));

        using var service = CreateService(backend);

        var exception = Assert.Throws<InvalidOperationException>(
            () => service.DeleteAdvancedRules(["Rule A"]));

        Assert.Contains("mutation failure", exception.Message);
        Assert.Equal("Rule A", Assert.Single(backend.Rules).Name);
    }

    [Fact]
    public void SetGroupEnabledState_UpdatesAllRulesInTheTargetGroup()
    {
        const string targetGroup = "Demo Group - MFW";
        var backend = new InMemoryFirewallBackend();
        backend.Seed(
            Snapshot("Rule A", targetGroup, enabled: true),
            Snapshot("Rule B", targetGroup, enabled: true),
            Snapshot("Other Rule", "Other Group - MFW", enabled: true));

        using var service = CreateService(backend);

        service.SetGroupEnabledState(targetGroup, false);

        Assert.All(
            backend.Rules.Where(rule => rule.Grouping == targetGroup),
            rule => Assert.False(rule.IsEnabled));
        Assert.True(Assert.Single(backend.Rules.Where(rule => rule.Name == "Other Rule")).IsEnabled);
    }

    [Fact]
    public void CreateAdvancedRule_StoresCreatedRuleInBackendState()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);
        var viewModel = new AdvancedRuleViewModel
        {
            Name = "Demo Rule",
            Status = "Block",
            IsEnabled = true,
            Direction = Directions.Outgoing,
            Protocol = 256,
            ApplicationName = "*",
            ServiceName = string.Empty,
            LocalPorts = "*",
            RemotePorts = "*",
            LocalAddresses = "*",
            RemoteAddresses = "*",
            Profiles = "All",
            Description = "Created by behavior test",
            Grouping = "Demo Group - MFW",
            InterfaceTypes = "All",
            IcmpTypesAndCodes = string.Empty
        };

        service.CreateAdvancedRule(viewModel, "All", string.Empty);

        var created = Assert.Single(backend.Rules);
        Assert.Equal("MFW - Demo Rule", created.Name);
        Assert.Equal(Directions.Outgoing, (Directions)created.Direction);
        Assert.False(created.IsAllow);
        Assert.Equal("Demo Group - MFW", created.Grouping);
        Assert.Contains("CreateRule:MFW - Demo Rule", backend.Operations);
    }

    private static FirewallActionsService CreateService(InMemoryFirewallBackend backend)
        => new(
            new UserActivityLogger(),
            null!,
            null!,
            null!,
            null!,
            null!,
            backend,
            backend,
            backend,
            backend,
            backend);

    private static FirewallRuleSnapshot Snapshot(
        string name,
        string grouping = "Demo Group - MFW",
        bool enabled = true)
        => new(
            name,
            "Description",
            enabled,
            (int)Directions.Outgoing,
            false,
            256,
            "*",
            string.Empty,
            "*",
            "*",
            "*",
            "*",
            0x7FFFFFFF,
            grouping,
            "All",
            string.Empty);
}
