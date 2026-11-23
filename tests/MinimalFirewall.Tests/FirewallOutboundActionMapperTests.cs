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
    public void UnsupportedPositiveValue_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            FirewallOutboundActionMapper.ToComAction((FirewallOutboundAction)999));
    }

    [Fact]
    public void UnsupportedNegativeValue_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            FirewallOutboundActionMapper.ToComAction((FirewallOutboundAction)(-1)));
    }
}
