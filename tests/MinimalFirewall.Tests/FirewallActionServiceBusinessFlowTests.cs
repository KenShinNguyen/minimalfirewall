using System;
using System.Linq;
using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallActionServiceBusinessFlowTests
{
    [Fact]
    public void ApplyApplicationRuleChange_ValidWindowsAppsPath_CreatesOutboundAllowRule()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);

        service.ApplyApplicationRuleChange(
            [@"C:\Program Files\WindowsApps\Contoso.App\app.exe"],
            "Allow Outbound");

        var rule = Assert.Single(backend.Rules);
        Assert.True(rule.IsAllow);
        Assert.Equal(Directions.Outgoing, (Directions)rule.Direction);
        Assert.Equal(@"C:\Program Files\WindowsApps\Contoso.App\app.exe", rule.ApplicationName);
        Assert.Contains("CreateRule:", backend.Operations.Single());
    }

    [Fact]
    public void ApplyApplicationRuleChange_BlockAll_CreatesInboundAndOutboundRules()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);

        service.ApplyApplicationRuleChange(
            [@"C:\Program Files\WindowsApps\Contoso.App\app.exe"],
            "Block (All)");

        Assert.Equal(2, backend.Rules.Count);
        Assert.All(backend.Rules, rule => Assert.False(rule.IsAllow));
        Assert.Contains(backend.Rules, r => (Directions)r.Direction == Directions.Incoming);
        Assert.Contains(backend.Rules, r => (Directions)r.Direction == Directions.Outgoing);
    }

    [Fact]
    public void ApplyApplicationRuleChange_WhitespacePath_DoesNotCallBackend()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);

        service.ApplyApplicationRuleChange(["   "], "Allow Outbound");

        Assert.Empty(backend.Rules);
        Assert.Empty(backend.Operations);
    }

    [Fact]
    public void ApplyApplicationRuleChange_WhenQueryFails_DoesNotMutateRules()
    {
        var backend = new InMemoryFirewallBackend { ThrowOnQuery = true };
        using var service = CreateService(backend);

        service.ApplyApplicationRuleChange(
            [@"C:\Program Files\WindowsApps\Contoso.App\app.exe"],
            "Allow Outbound");

        Assert.Empty(backend.Rules);
    }

    [Fact]
    public void DeleteAdvancedRules_WhenRuleExists_RemovesViaBackend()
    {
        var backend = new InMemoryFirewallBackend();
        backend.Seed(new FirewallRuleSnapshot(
            "Rule A", "Description", true, (int)Directions.Outgoing, false, 256,
            @"C:\app.exe", "", "*", "*", "*", "*", 0x7FFFFFFF, "Demo Group - MFW", "All", ""));

        using var service = CreateService(backend);

        service.DeleteAdvancedRules(["Rule A"]);

        Assert.Empty(backend.Rules);
        Assert.Contains("DeleteByName", backend.Operations);
    }

    [Fact]
    public void DeleteAdvancedRules_WhenRuleMissing_CompletesWithoutThrowing()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);

        service.DeleteAdvancedRules(["Missing"]);

        Assert.Empty(backend.Rules);
        Assert.Contains("DeleteByName", backend.Operations);
    }

    [Fact]
    public void CreateAdvancedRule_ValidModel_StoresAllowRule()
    {
        var backend = new InMemoryFirewallBackend();
        using var service = CreateService(backend);

        service.CreateAdvancedRule(
            new AdvancedRuleViewModel
            {
                Name = "Allow Client",
                Status = "Allow",
                IsEnabled = true,
                Direction = Directions.Outgoing,
                Protocol = 6,
                ApplicationName = @"C:\Program Files\WindowsApps\Contoso.App\client.exe",
                Profiles = "All",
                LocalPorts = "*",
                RemotePorts = "*",
                LocalAddresses = "*",
                RemoteAddresses = "*",
                Grouping = "Demo Group - MFW"
            },
            "All",
            string.Empty);

        var rule = Assert.Single(backend.Rules);
        Assert.True(rule.IsAllow);
        Assert.Equal(6, rule.Protocol);
    }

    private static FirewallActionsService CreateService(InMemoryFirewallBackend backend)
        => new(
            new UserActivityLogger(),
            null!,
            null!,
            null!,
            new WildcardRuleService(Path.Combine(Path.GetTempPath(), $"mfw-wild-{Guid.NewGuid():N}.json")),
            new FirewallDataService(
                new WildcardRuleService(Path.Combine(Path.GetTempPath(), $"mfw-data-wild-{Guid.NewGuid():N}.json")),
                null!,
                null!,
                backend),
            backend,
            backend,
            backend,
            backend,
            backend);
}
