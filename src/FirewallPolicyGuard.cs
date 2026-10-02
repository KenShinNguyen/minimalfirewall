using NetFwTypeLib;

namespace MinimalFirewall;

/// <summary>
/// Keeps the safety decision around Lockdown mode independent of the COM implementation.
/// Unknown is deliberately not treated as Allow.
/// </summary>
public static class FirewallPolicyGuard
{
    public static bool TryGetToggleAction(
        FirewallPolicyState currentState,
        out NET_FW_ACTION_ targetAction)
    {
        switch (currentState)
        {
            case FirewallPolicyState.Allow:
                targetAction = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                return true;

            case FirewallPolicyState.Block:
                targetAction = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                return true;

            default:
                targetAction = default;
                return false;
        }
    }

    public static bool TryToggle(
        IFirewallBackend backend,
        out SetDefaultOutboundActionResult? result)
    {
        ArgumentNullException.ThrowIfNull(backend);

        if (!TryGetToggleAction(backend.GetDefaultOutboundState(), out var targetAction))
        {
            result = null;
            return false;
        }

        result = backend.SetDefaultOutboundAction(targetAction);
        return result.Succeeded;
    }
}
