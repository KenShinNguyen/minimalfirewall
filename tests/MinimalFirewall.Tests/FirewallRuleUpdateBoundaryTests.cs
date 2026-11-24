using System.Reflection;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleUpdateBoundaryTests
{
    [Fact]
    public void UpdateBackendContract_IsComFree()
    {
        var method = typeof(IFirewallRuleUpdateBackend).GetMethod(nameof(IFirewallRuleUpdateBackend.UpdateRemoteAddresses));

        Assert.NotNull(method);
        Assert.Equal(typeof(void), method!.ReturnType);
        Assert.Equal(typeof(string), method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(string), method.GetParameters()[1].ParameterType);

        Assert.DoesNotContain(
            method.GetParameters().Select(p => p.ParameterType),
            type => type.FullName?.Contains("NetFwTypeLib", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void FakeUpdateBackend_ReceivesRuleNameAndAddresses()
    {
        var backend = new FakeUpdateBackend();

        backend.UpdateRemoteAddresses("Demo Rule", "10.0.0.1,10.0.0.2");

        Assert.Equal("Demo Rule", backend.RuleName);
        Assert.Equal("10.0.0.1,10.0.0.2", backend.RemoteAddresses);
    }

    private sealed class FakeUpdateBackend : IFirewallRuleUpdateBackend
    {
        public string? RuleName { get; private set; }
        public string? RemoteAddresses { get; private set; }

        public void UpdateRemoteAddresses(string ruleName, string newRemoteAddresses)
        {
            RuleName = ruleName;
            RemoteAddresses = newRemoteAddresses;
        }
    }
}
