namespace MinimalFirewall;

internal enum FirewallOutboundAction
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

    public static FirewallOutboundAction FromComAction(NetFwTypeLib.NET_FW_ACTION_ action)
        => action switch
        {
            NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_ALLOW => FirewallOutboundAction.Allow,
            NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_BLOCK => FirewallOutboundAction.Block,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported Windows Firewall action.")
        };
}
