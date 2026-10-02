using NetFwTypeLib;

namespace MinimalFirewall;

/// <summary>
/// Testable boundary between application logic and the Windows Firewall backend.
/// Keep UI/business logic dependent on this contract instead of directly reaching COM.
/// </summary>
public interface IFirewallBackend
{
    FirewallPolicyState GetDefaultOutboundState();

    SetDefaultOutboundActionResult SetDefaultOutboundAction(NET_FW_ACTION_ action);
}

/// <summary>
/// Production adapter for the existing Windows Firewall implementation.
/// FirewallRuleService remains the single owner of NetFwTypeLib policy mechanics.
/// </summary>
public sealed class WindowsFirewallBackend : IFirewallBackend
{
    public FirewallPolicyState GetDefaultOutboundState()
        => FirewallRuleService.GetDefaultOutboundState();

    public SetDefaultOutboundActionResult SetDefaultOutboundAction(NET_FW_ACTION_ action)
        => FirewallRuleService.SetDefaultOutboundAction(action);
}
