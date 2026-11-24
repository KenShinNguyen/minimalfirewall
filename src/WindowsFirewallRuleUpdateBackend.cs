using NetFwTypeLib;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

/// <summary>
/// Windows Firewall implementation of mutable rule updates.
/// All COM acquisition and release remains inside this backend.
/// </summary>
public sealed class WindowsFirewallRuleUpdateBackend : IFirewallRuleUpdateBackend
{
    private static readonly Type? FwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    public void UpdateRemoteAddresses(string ruleName, string newRemoteAddresses)
    {
        if (string.IsNullOrEmpty(ruleName) || string.IsNullOrEmpty(newRemoteAddresses))
        {
            return;
        }

        if (FwPolicyType is null)
        {
            Debug.WriteLine("[ERROR] UpdateRemoteAddresses: Firewall policy COM type could not be loaded.");
            return;
        }

        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? rulesCollection = null;
        INetFwRule2? rule = null;

        try
        {
            firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicyType)!;
            rulesCollection = firewallPolicy.Rules;

            if (rulesCollection.Item(ruleName) is not INetFwRule2 matchedRule)
            {
                return;
            }

            rule = matchedRule;
            rule.RemoteAddresses = newRemoteAddresses;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ERROR] UpdateRemoteAddresses ('{ruleName}'): Failed. {ex.Message}");
        }
        finally
        {
            if (rule != null)
            {
                Marshal.ReleaseComObject(rule);
            }

            if (rulesCollection != null)
            {
                Marshal.ReleaseComObject(rulesCollection);
            }

            if (firewallPolicy != null)
            {
                Marshal.ReleaseComObject(firewallPolicy);
            }
        }
    }
}
