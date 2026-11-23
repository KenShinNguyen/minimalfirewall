namespace MinimalFirewall;

/// <summary>
/// Keeps the safety decision around Lockdown mode independent of the COM implementation.
/// Unknown is deliberately not treated as Allow.
/// </summary>
public static class FirewallPolicyGuard
{
    public static bool TryGetToggleAction(
        FirewallPolicyState currentState,
        out FirewallOutboundAction targetAction)
    {
        switch (currentState)
        {
            case FirewallPolicyState.Allow:
                targetAction = FirewallOutboundAction.Block;
                return true;

            case FirewallPolicyState.Block:
                targetAction = FirewallOutboundAction.Allow;
                return true;

            default:
                targetAction = default;
                return false;
        }
    }

    public static bool TryGetToggleAction(
        IFirewallBackend backend,
        out FirewallOutboundAction targetAction)
    {
        ArgumentNullException.ThrowIfNull(backend);

        try
        {
            return TryGetToggleAction(
                backend.GetDefaultOutboundState(),
                out targetAction);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[ERROR] FirewallPolicyGuard.TryGetToggleAction: {ex.GetType().Name}: {ex.Message}");

            targetAction = default;
            return false;
        }
    }

    public static bool TrySetDefaultOutboundAction(
        IFirewallBackend backend,
        FirewallOutboundAction action,
        out FirewallPolicyOperationResult? result)
    {
        ArgumentNullException.ThrowIfNull(backend);

        try
        {
            result = backend.SetDefaultOutboundAction(action);
            return result?.Succeeded == true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[ERROR] FirewallPolicyGuard.TrySetDefaultOutboundAction: {ex.GetType().Name}: {ex.Message}");

            result = null;
            return false;
        }
    }

    public static bool TryToggle(
        IFirewallBackend backend,
        out FirewallPolicyOperationResult? result)
    {
        ArgumentNullException.ThrowIfNull(backend);

        try
        {
            if (!TryGetToggleAction(backend.GetDefaultOutboundState(), out var targetAction))
            {
                result = null;
                return false;
            }

            result = backend.SetDefaultOutboundAction(targetAction);
            return result?.Succeeded == true;
        }
        catch (Exception ex)
        {
            // Lockdown toggling is fail-safe: a backend read/write failure must never
            // be interpreted as a successful policy transition.
            System.Diagnostics.Debug.WriteLine(
                $"[ERROR] FirewallPolicyGuard.TryToggle: {ex.GetType().Name}: {ex.Message}");

            result = null;
            return false;
        }
    }
}
