using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

public sealed class WindowsFirewallBackend : IFirewallBackend
{
    public FirewallPolicyState GetDefaultOutboundState()
    {
        NET_FW_ACTION_? action = TryGetDefaultOutboundAction();
        if (action == null)
        {
            return FirewallPolicyState.Unknown;
        }

        return action.Value == NET_FW_ACTION_.NET_FW_ACTION_BLOCK
            ? FirewallPolicyState.Block
            : FirewallPolicyState.Allow;
    }

    public FirewallPolicyOperationResult SetDefaultOutboundAction(FirewallOutboundAction action)
        => ToPolicyOperationResult(
            SetDefaultOutboundActionCore(action),
            action);

    private const int E_ACCESSDENIED = unchecked((int)0x80070005);
    private static readonly Type? _firewallPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    private static readonly NET_FW_PROFILE_TYPE2_[] AllProfiles =
    [
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
    ];

    private static INetFwPolicy2 GetLocalPolicy()
    {
        if (_firewallPolicyType == null)
        {
            throw new InvalidOperationException("Firewall policy type could not be retrieved.");
        }
        return (INetFwPolicy2)Activator.CreateInstance(_firewallPolicyType)!;
    }

    private static string DescribeComError(COMException ex)
    {
        return ex.HResult == E_ACCESSDENIED
            ? "Access denied - administrator privileges are required."
            : $"HResult 0x{ex.HResult:X8}: {ex.Message}";
    }

    private static NET_FW_ACTION_? TryGetDefaultOutboundAction()
    {
        INetFwPolicy2? firewallPolicy;
        try { firewallPolicy = GetLocalPolicy(); }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ERROR] TryGetDefaultOutboundAction: Could not open firewall policy. {ex.Message}");
            return null;
        }

        if (firewallPolicy == null) return null;

        try
        {
            var currentProfileTypes = (NET_FW_PROFILE_TYPE2_)firewallPolicy.CurrentProfileTypes;
            if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) != 0)
                return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC];
            if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) != 0)
                return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE];
            if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) != 0)
                return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN];

            Debug.WriteLine("[WARN] TryGetDefaultOutboundAction: No specific profile type identified as active. Falling back to Public.");
            return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC];
        }
        catch (COMException ex)
        {
            Debug.WriteLine($"[ERROR] TryGetDefaultOutboundAction: Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
            return null;
        }
        finally { Marshal.ReleaseComObject(firewallPolicy); }
    }

    private static SetDefaultOutboundActionResult SetDefaultOutboundActionCore(FirewallOutboundAction requestedAction)
    {
        NET_FW_ACTION_ action = FirewallOutboundActionMapper.ToComAction(requestedAction);

        INetFwPolicy2? firewallPolicy;
        try { firewallPolicy = GetLocalPolicy(); }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ERROR] SetDefaultOutboundAction: Could not open firewall policy. {ex.Message}");
            return new SetDefaultOutboundActionResult { RequestedAction = requestedAction, PolicyUnavailable = true };
        }

        if (firewallPolicy == null)
            return new SetDefaultOutboundActionResult { RequestedAction = requestedAction, PolicyUnavailable = true };

        var results = new List<ProfileActionResult>();
        var changed = new List<(NET_FW_PROFILE_TYPE2_ Profile, NET_FW_ACTION_ Previous)>();

        try
        {
            foreach (NET_FW_PROFILE_TYPE2_ profile in AllProfiles)
            {
                NET_FW_ACTION_ previous;
                try { previous = firewallPolicy.DefaultOutboundAction[profile]; }
                catch (COMException ex)
                {
                    Debug.WriteLine($"[ERROR] SetDefaultOutboundAction ({profile}): Could not read current action. HResult: 0x{ex.HResult:X8}.");
                    results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = false, Error = DescribeComError(ex) });
                    continue;
                }

                if (previous == action)
                {
                    results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = true, PreviousAction = FirewallOutboundActionMapper.TryFromComAction(previous) });
                    continue;
                }

                try { firewallPolicy.set_DefaultOutboundAction(profile, action); }
                catch (COMException ex)
                {
                    Debug.WriteLine($"[ERROR] SetDefaultOutboundAction ({profile}): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                    results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = false, PreviousAction = FirewallOutboundActionMapper.TryFromComAction(previous), Error = DescribeComError(ex) });
                    continue;
                }

                NET_FW_ACTION_ verified;
                try { verified = firewallPolicy.DefaultOutboundAction[profile]; }
                catch (COMException ex)
                {
                    changed.Add((profile, previous));
                    results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = false, PreviousAction = FirewallOutboundActionMapper.TryFromComAction(previous), Error = $"Could not verify the change: {DescribeComError(ex)}" });
                    continue;
                }

                if (verified != action)
                {
                    results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = false, PreviousAction = FirewallOutboundActionMapper.TryFromComAction(previous), Error = "The policy did not retain the requested action (it may be overridden by Group Policy)." });
                    continue;
                }

                changed.Add((profile, previous));
                results.Add(new ProfileActionResult { Profile = (int)profile, Succeeded = true, PreviousAction = FirewallOutboundActionMapper.TryFromComAction(previous) });
            }

            bool anyFailed = results.Exists(r => !r.Succeeded);
            bool rolledBack = false;
            bool rollbackIncomplete = false;

            if (anyFailed && changed.Count > 0)
            {
                rolledBack = true;
                foreach (var (profile, previous) in changed)
                {
                    try { firewallPolicy.set_DefaultOutboundAction(profile, previous); }
                    catch (COMException ex)
                    {
                        rollbackIncomplete = true;
                        Debug.WriteLine($"[ERROR] SetDefaultOutboundAction rollback ({profile}): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                    }
                }
            }

            return new SetDefaultOutboundActionResult
            {
                RequestedAction = requestedAction,
                Profiles = results,
                RolledBack = rolledBack,
                RollbackIncomplete = rollbackIncomplete
            };
        }
        finally { Marshal.ReleaseComObject(firewallPolicy); }
    }

    private static FirewallPolicyOperationResult ToPolicyOperationResult(
        SetDefaultOutboundActionResult result,
        FirewallOutboundAction requestedAction)
        => new()
        {
            RequestedAction = requestedAction,
            Succeeded = result.Succeeded,
            RolledBack = result.RolledBack,
            RollbackIncomplete = result.RollbackIncomplete,
            DiagnosticSummary = result.BuildSummary()
        };
}


internal static class FirewallOutboundActionMapper
{
    public static NET_FW_ACTION_ ToComAction(FirewallOutboundAction action)
        => action switch
        {
            FirewallOutboundAction.Allow => NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            FirewallOutboundAction.Block => NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported firewall outbound action.")
        };

    /// <summary>
    /// Lenient inverse used when recording diagnostics: an unrecognised COM value
    /// becomes null instead of throwing in the middle of a policy change.
    /// </summary>
    public static FirewallOutboundAction? TryFromComAction(NET_FW_ACTION_ action)
        => action switch
        {
            NET_FW_ACTION_.NET_FW_ACTION_ALLOW => FirewallOutboundAction.Allow,
            NET_FW_ACTION_.NET_FW_ACTION_BLOCK => FirewallOutboundAction.Block,
            _ => null
        };

    public static FirewallOutboundAction FromComAction(NET_FW_ACTION_ action)
        => action switch
        {
            NET_FW_ACTION_.NET_FW_ACTION_ALLOW => FirewallOutboundAction.Allow,
            NET_FW_ACTION_.NET_FW_ACTION_BLOCK => FirewallOutboundAction.Block,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported firewall COM action.")
        };
}
