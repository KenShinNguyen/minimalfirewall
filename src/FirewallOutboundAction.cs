namespace MinimalFirewall;

public enum FirewallOutboundAction
{
    Allow,
    Block
}

internal static class FirewallOutboundActionMapper
{
    public static NetFwTypeLib.NET_FW_ACTION_ ToComAction(FirewallOutboundAction action)
        => action switch
        {
            FirewallOutboundAction.Allow => NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            FirewallOutboundAction.Block => NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported firewall outbound action.")
        };

}
