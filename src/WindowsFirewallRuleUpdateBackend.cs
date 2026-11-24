using NetFwTypeLib;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

/// <summary>
/// Windows Firewall implementation of mutable rule updates.
/// COM acquisition, exception mapping, and release remain inside this backend.
/// </summary>
public sealed class WindowsFirewallRuleUpdateBackend : IFirewallRuleUpdateBackend
{
    private static readonly Type? FwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    public FirewallRuleUpdateResult UpdateRemoteAddresses(string ruleName, string newRemoteAddresses)
    {
        if (string.IsNullOrWhiteSpace(ruleName) || string.IsNullOrWhiteSpace(newRemoteAddresses))
        {
            return FirewallRuleUpdateResult.Failure(
                FirewallRuleUpdateErrorCode.InvalidRequest,
                "Rule name and remote addresses are required.");
        }

        if (FwPolicyType is null)
        {
            return FirewallRuleUpdateResult.Failure(
                FirewallRuleUpdateErrorCode.FirewallUnavailable,
                "Windows Firewall policy COM class is unavailable.");
        }

        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? rulesCollection = null;
        INetFwRule2? rule = null;

        try
        {
            firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicyType)!;
            rulesCollection = firewallPolicy.Rules;

            object matchedRuleObject = rulesCollection.Item(ruleName);
            if (matchedRuleObject is not INetFwRule2 matchedRule)
            {
                ReleaseComObject(matchedRuleObject);
                return FirewallRuleUpdateResult.Failure(
                    FirewallRuleUpdateErrorCode.RuleNotFound,
                    $"Firewall rule '{ruleName}' was not found or cannot be updated.");
            }

            rule = matchedRule;
            rule.RemoteAddresses = newRemoteAddresses;
            return FirewallRuleUpdateResult.Success();
        }
        catch (Exception ex)
        {
            var errorCode = FirewallRuleUpdateErrorMapper.FromHResult(ex.HResult);
            string error = errorCode switch
            {
                FirewallRuleUpdateErrorCode.AccessDenied =>
                    "Windows Firewall denied the rule update. Check administrator permissions.",
                FirewallRuleUpdateErrorCode.RuleNotFound =>
                    $"Firewall rule '{ruleName}' was not found.",
                _ =>
                    $"Windows Firewall rule update failed: {ex.Message}"
            };

            Debug.WriteLine(
                $"[ERROR] UpdateRemoteAddresses ('{ruleName}'): {error} HRESULT: 0x{ex.HResult:X8}.");

            return FirewallRuleUpdateResult.Failure(errorCode, error, ex.HResult);
        }
        finally
        {
            ReleaseComObject(rule);
            ReleaseComObject(rulesCollection);
            ReleaseComObject(firewallPolicy);
        }
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is null)
        {
            return;
        }

        try
        {
            if (Marshal.IsComObject(value))
            {
                Marshal.ReleaseComObject(value);
            }
        }
        catch (Exception ex)
        {
            // Cleanup must not replace the operation result with a second failure.
            Debug.WriteLine($"[WARN] Could not release a firewall COM object: {ex.Message}");
        }
    }
}
