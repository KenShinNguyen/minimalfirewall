using NetFwTypeLib;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallPolicyGuardTests
{
    [Fact]
    public void UnknownState_MustRefuseToggle()
    {
        var toggled = FirewallPolicyGuard.TryGetToggleAction(
            FirewallPolicyState.Unknown,
            out var action);

        Assert.False(toggled);
        Assert.Equal(default, action);
    }

    [Fact]
    public void AllowState_TogglesToBlock()
    {
        var toggled = FirewallPolicyGuard.TryGetToggleAction(
            FirewallPolicyState.Allow,
            out var action);

        Assert.True(toggled);
        Assert.Equal(NET_FW_ACTION_.NET_FW_ACTION_BLOCK, action);
    }

    [Fact]
    public void BlockState_TogglesToAllow()
    {
        var toggled = FirewallPolicyGuard.TryGetToggleAction(
            FirewallPolicyState.Block,
            out var action);

        Assert.True(toggled);
        Assert.Equal(NET_FW_ACTION_.NET_FW_ACTION_ALLOW, action);
    }
}
