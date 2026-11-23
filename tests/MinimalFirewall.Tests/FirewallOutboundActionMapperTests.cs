using NetFwTypeLib;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallOutboundActionMapperTests
{
    [Fact]
    public void Allow_MapsToComAllow()
    {
        Assert.Equal(
            NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            FirewallOutboundActionMapper.ToComAction(FirewallOutboundAction.Allow));
    }

    [Fact]
    public void Block_MapsToComBlock()
    {
        Assert.Equal(
            NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            FirewallOutboundActionMapper.ToComAction(FirewallOutboundAction.Block));
    }

    [Fact]
    public void ComAllow_MapsToAllow()
    {
        Assert.Equal(
            FirewallOutboundAction.Allow,
            FirewallOutboundActionMapper.FromComAction(NET_FW_ACTION_.NET_FW_ACTION_ALLOW));
    }

    [Fact]
    public void ComBlock_MapsToBlock()
    {
        Assert.Equal(
            FirewallOutboundAction.Block,
            FirewallOutboundActionMapper.FromComAction(NET_FW_ACTION_.NET_FW_ACTION_BLOCK));
    }
}
