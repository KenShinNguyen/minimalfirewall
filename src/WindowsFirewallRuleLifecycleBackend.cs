using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

public sealed class WindowsFirewallRuleLifecycleBackend : IFirewallRuleLifecycleBackend
{
    private readonly FirewallRuleService _firewallService;

    public WindowsFirewallRuleLifecycleBackend(FirewallRuleService firewallService)
    {
        _firewallService = firewallService;
    }

    public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths)
        => Execute(() => FirewallRuleService.DeleteRulesByPath([.. appPaths]), "delete rules by path");

    public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames)
        => Execute(() => FirewallRuleService.DeleteUwpRules([.. packageFamilyNames]), "delete UWP rules");

    public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames)
        => Execute(() => FirewallRuleService.DeleteRulesByName([.. ruleNames]), "delete rules by name");

    public FirewallRuleLifecycleOperationResult DeleteByDescription(string description)
        => Execute(() => FirewallRuleService.DeleteRulesByDescription(description), "delete rules by description");

    public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName)
        => Execute(() => FirewallRuleService.DeleteRulesByGroup(groupName), "delete rules by group");

    public FirewallRuleLifecycleOperationResult DeleteAllMfwRules()
        => Execute(FirewallRuleService.DeleteAllMfwRules, "delete all Minimal Firewall rules");

    public FirewallRuleLifecycleOperationResult EnableByName(string ruleName)
        => Execute(() => _firewallService.EnableRuleByName(ruleName), "enable rule");

    public FirewallRuleLifecycleOperationResult DisableByName(string ruleName)
        => Execute(() => _firewallService.DisableRuleByName(ruleName), "disable rule");

    private static FirewallRuleLifecycleOperationResult Execute(
        Action operation,
        string operationName)
    {
        try
        {
            operation();
            return FirewallRuleLifecycleOperationResult.Success();
        }
        catch (COMException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed: {ex.Message}", ex);
        }
    }
}
