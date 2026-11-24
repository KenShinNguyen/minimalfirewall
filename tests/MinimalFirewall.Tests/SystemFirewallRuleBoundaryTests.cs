using Xunit;

namespace MinimalFirewall.Tests;

public sealed class SystemFirewallRuleBoundaryTests
{
    [Fact]
    public void ManageSystemRule_EnableNewRule_DelegatesEnsureWithoutDuplicate()
    {
        var backend = new FakeSystemFirewallRuleBackend();
        var service = new TestableFirewallActionsService(backend);

        var succeeded = service.CallManageSystemRule("System Rule", "Description", "svchost.exe", "CryptSvc", SystemFirewallRuleProtocol.Tcp, "80,443", "*", true);

        Assert.True(succeeded);
        Assert.Single(backend.EnsureCalls);
        Assert.Empty(backend.RemoveCalls);
        Assert.Equal("System Rule", backend.EnsureCalls[0].Name);
    }

    [Fact]
    public void ManageSystemRule_EnableExistingDisabledRule_UsesEnsureWithoutDuplicate()
    {
        var backend = new FakeSystemFirewallRuleBackend();
        var service = new TestableFirewallActionsService(backend);

        var succeeded = service.CallManageSystemRule("Existing Disabled Rule", "Description", "svchost.exe", "Dhcp", SystemFirewallRuleProtocol.Udp, "67", "68", true);

        Assert.True(succeeded);
        Assert.Single(backend.EnsureCalls);
        Assert.Empty(backend.RemoveCalls);
    }

    [Fact]
    public void ManageSystemRule_DisableExistingRule_DelegatesRemove()
    {
        var backend = new FakeSystemFirewallRuleBackend();
        var service = new TestableFirewallActionsService(backend);

        var succeeded = service.CallManageSystemRule("System Rule", "Description", "svchost.exe", "CryptSvc", SystemFirewallRuleProtocol.Tcp, "80,443", "*", false);

        Assert.True(succeeded);
        Assert.Empty(backend.EnsureCalls);
        Assert.Single(backend.RemoveCalls);
        Assert.Equal("System Rule", backend.RemoveCalls[0]);
    }

    [Fact]
    public void ToggleLockdown_SystemRuleBackendFailure_FailsClosedAndNotifies()
    {
        var policyBackend = new FakeFirewallBackend(FirewallPolicyState.Allow);
        var systemBackend = new FakeSystemFirewallRuleBackend
        {
            EnsureResult = SystemFirewallRuleOperationResult.Failure("system rule backend failed")
        };
        var service = new FailingPreparationFirewallActionsService(policyBackend, systemBackend);

        service.ToggleLockdown();

        Assert.Equal(1, service.PrepareCalls);
        Assert.Equal(0, service.CompleteCalls);
        Assert.Single(service.LockdownMessages);
        Assert.Equal("Lockdown Error", service.LockdownMessages[0].Caption);
        Assert.Contains("system rule backend failed", service.LockdownMessages[0].Text);
    }

    [Fact]
    public void Mapper_MapsDirectionExplicitly()
    {
        Assert.Equal(NetFwTypeLib.NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT,
            SystemFirewallRuleMapper.ToComDirection(SystemFirewallRuleDirection.Outbound));
    }

    [Fact]
    public void Mapper_MapsActionExplicitly()
    {
        Assert.Equal(NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            SystemFirewallRuleMapper.ToComAction(SystemFirewallRuleAction.Allow));
    }

    [Fact]
    public void Mapper_MapsProtocolExplicitly()
    {
        Assert.Equal(256, SystemFirewallRuleMapper.ToComProtocol(SystemFirewallRuleProtocol.Any));
        Assert.Equal(6, SystemFirewallRuleMapper.ToComProtocol(SystemFirewallRuleProtocol.Tcp));
        Assert.Equal(17, SystemFirewallRuleMapper.ToComProtocol(SystemFirewallRuleProtocol.Udp));
    }

    [Fact]
    public void Mapper_MapsEnabledExplicitly()
    {
        Assert.True(SystemFirewallRuleMapper.ToComEnabled(true));
        Assert.False(SystemFirewallRuleMapper.ToComEnabled(false));
    }

    [Fact]
    public void Mapper_RejectsUnsupportedProtocol()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SystemFirewallRuleMapper.ToComProtocol((SystemFirewallRuleProtocol)999));
    }

    private sealed class TestableFirewallActionsService(ISystemFirewallRuleBackend systemBackend)
        : FirewallActionsService(
            null!, new UserActivityLogger(), null!, null!, null!, null!, null!,
            new FakeFirewallBackend(FirewallPolicyState.Allow), systemBackend)
    {
        public bool CallManageSystemRule(string ruleName, string description, string applicationName,
            string serviceName, SystemFirewallRuleProtocol protocol, string remotePorts,
            string localPorts, bool enable)
            => ManageSystemRule(ruleName, description, applicationName, serviceName, protocol,
                remotePorts, localPorts, enable);
    }

    private sealed class FailingPreparationFirewallActionsService(
        IFirewallBackend policyBackend, ISystemFirewallRuleBackend systemBackend)
        : FirewallActionsService(
            null!, new UserActivityLogger(), null!, null!, null!, null!, null!,
            policyBackend, systemBackend)
    {
        public int PrepareCalls { get; private set; }
        public int CompleteCalls { get; private set; }
        public List<LockdownMessage> LockdownMessages { get; } = [];

        protected override void PrepareLockdownPrerequisites(bool enableLockdown)
        {
            PrepareCalls++;
            if (!ManageSystemRule("System Rule", "Description", "svchost.exe", "CryptSvc",
                    SystemFirewallRuleProtocol.Tcp, "80,443", "*", enableLockdown))
            {
                throw new InvalidOperationException("system rule backend failed");
            }
        }

        protected override void CompleteLockdownTransition(bool lockdownEnabled) => CompleteCalls++;

        protected override void ShowLockdownMessage(string text, string caption) =>
            LockdownMessages.Add(new LockdownMessage(text, caption));
    }

    private sealed record LockdownMessage(string Text, string Caption);

    private sealed class FakeSystemFirewallRuleBackend : ISystemFirewallRuleBackend
    {
        public List<SystemFirewallRuleDefinition> EnsureCalls { get; } = [];
        public List<string> RemoveCalls { get; } = [];
        public SystemFirewallRuleOperationResult EnsureResult { get; set; } =
            SystemFirewallRuleOperationResult.Success();
        public SystemFirewallRuleOperationResult RemoveResult { get; set; } =
            SystemFirewallRuleOperationResult.Success();

        public SystemFirewallRuleOperationResult EnsureRule(SystemFirewallRuleDefinition definition)
        {
            EnsureCalls.Add(definition);
            return EnsureResult;
        }

        public SystemFirewallRuleOperationResult RemoveRule(string ruleName)
        {
            RemoveCalls.Add(ruleName);
            return RemoveResult;
        }
    }

    private sealed class FakeFirewallBackend(FirewallPolicyState state) : IFirewallBackend
    {
        public FirewallPolicyState GetDefaultOutboundState() => state;

        public FirewallPolicyOperationResult SetDefaultOutboundAction(FirewallOutboundAction action) =>
            new() { RequestedAction = action, Succeeded = true };
    }
}
