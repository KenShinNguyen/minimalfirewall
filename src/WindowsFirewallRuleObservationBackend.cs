using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace MinimalFirewall;

/// <summary>
/// Windows Firewall implementation of the sentry observation boundary.
/// All NetFwTypeLib COM ownership stays inside this class.
/// </summary>
public sealed class WindowsFirewallRuleObservationBackend : IFirewallRuleObservationBackend
{
    public AdvancedRuleViewModel? GetRuleByName(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return null;
        }

        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? rulesCollection = null;
        INetFwRule2? rule = null;

        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (policyType == null)
            {
                return null;
            }

            firewallPolicy = (INetFwPolicy2?)Activator.CreateInstance(policyType);
            if (firewallPolicy == null)
            {
                return null;
            }

            rulesCollection = firewallPolicy.Rules;
            if (rulesCollection == null)
            {
                return null;
            }

            try
            {
                rule = rulesCollection.Item(ruleName) as INetFwRule2;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] GetRuleByName ('{ruleName}'): {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}");
                return null;
            }

            return rule == null
                ? null
                : FirewallDataService.CreateAdvancedRuleViewModel(WindowsFirewallRuleQueryBackend.CreateSnapshot(rule));
        }
        catch (COMException ex)
        {
            Debug.WriteLine($"[ERROR] GetRuleByName ('{ruleName}'): {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}");
            return null;
        }
        catch (InvalidOperationException ex)
        {
            Debug.WriteLine($"[ERROR] GetRuleByName ('{ruleName}'): {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}");
            return null;
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

    public List<AdvancedRuleViewModel> GetForeignRules(
        IProgress<int>? progress = null,
        CancellationToken token = default)
    {
        var rules = new List<AdvancedRuleViewModel>();
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (policyType == null)
        {
            return rules;
        }

        var firewallPolicy = (INetFwPolicy2?)Activator.CreateInstance(policyType);
        if (firewallPolicy?.Rules == null)
        {
            return rules;
        }

        var comRules = firewallPolicy.Rules;
        try
        {
            int totalRules = comRules.Count;
            if (totalRules == 0)
            {
                progress?.Report(100);
                return rules;
            }

            int processedRules = 0;
            foreach (INetFwRule2 rule in comRules)
            {
                if (token.IsCancellationRequested)
                {
                    break;
                }

                processedRules++;
                progress?.Report((processedRules * 100) / totalRules);

                if (rule == null)
                {
                    continue;
                }

                try
                {
                    string ruleName = rule.Name;
                    if (string.IsNullOrEmpty(ruleName) || IsMfwRule(rule.Grouping))
                    {
                        continue;
                    }

                    rules.Add(FirewallDataService.CreateAdvancedRuleViewModel(WindowsFirewallRuleQueryBackend.CreateSnapshot(rule)));
                }
                finally
                {
                    Marshal.ReleaseComObject(rule);
                }
            }
        }
        finally
        {
            if (comRules != null)
            {
                Marshal.ReleaseComObject(comRules);
            }

            if (firewallPolicy != null)
            {
                Marshal.ReleaseComObject(firewallPolicy);
            }
        }

        return rules;
    }

    private static bool IsMfwRule(string? grouping)
    {
        if (string.IsNullOrEmpty(grouping))
        {
            return false;
        }

        return grouping.EndsWith(MFWConstants.MfwRuleSuffix) ||
               grouping == MFWConstants.MainRuleGroup ||
               grouping == MFWConstants.WildcardRuleGroup;
    }
}
