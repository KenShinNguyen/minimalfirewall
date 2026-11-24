using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using NetFwTypeLib;

namespace MinimalFirewall;

/// <summary>
/// Windows implementation of <see cref="IFirewallRuleQueryBackend"/>. This is the only place that
/// touches INetFwRule2 / INetFwRules / INetFwPolicy2 for rule queries and group state, and it owns
/// the release of every COM object it creates or receives.
/// </summary>
public sealed class WindowsFirewallRuleQueryBackend : IFirewallRuleQueryBackend
{
    private static readonly Type? FwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules()
        => Execute("query Minimal Firewall rules", () =>
        {
            var summaries = new List<FirewallRuleSummary>();
            var failures = new List<FirewallRuleOperationFailure>();

            ForEachRule(rule =>
            {
                // Read the cheap grouping property first so non-MFW rules cost a single COM read.
                string grouping = rule.Grouping;
                if (!MfwRuleGroups.IsMfwGroup(grouping))
                {
                    return;
                }

                summaries.Add(new FirewallRuleSummary(
                    rule.Name ?? string.Empty,
                    rule.ApplicationName ?? string.Empty,
                    grouping,
                    rule.Protocol,
                    rule.Action == NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
                    rule.LocalPorts ?? string.Empty,
                    rule.RemotePorts ?? string.Empty));
            }, failures);

            return FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success(summaries, failures);
        });

    public FirewallRuleQueryResult<int> EnableMfwRules()
        => Execute("enable Minimal Firewall rules", () =>
        {
            int enabledCount = 0;
            var failures = new List<FirewallRuleOperationFailure>();

            ForEachRule(rule =>
            {
                if (!MfwRuleGroups.IsReenableTargetGroup(rule.Grouping))
                {
                    return;
                }

                if (!rule.Enabled)
                {
                    rule.Enabled = true;
                    enabledCount++;
                }
            }, failures);

            return FirewallRuleQueryResult<int>.Success(enabledCount, failures);
        });

    public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled)
        => Execute("set group enabled state", () =>
        {
            if (FwPolicyType == null)
            {
                return FirewallRuleQueryResult<int>.Failure("Windows Firewall policy COM type is unavailable.");
            }

            INetFwPolicy2? firewallPolicy = null;
            INetFwRules? comRules = null;
            var rulesInGroup = new List<INetFwRule2>();
            var failures = new List<FirewallRuleOperationFailure>();
            int changedCount = 0;

            try
            {
                firewallPolicy = Activator.CreateInstance(FwPolicyType) as INetFwPolicy2;
                if (firewallPolicy == null)
                {
                    return FirewallRuleQueryResult<int>.Failure("Windows Firewall policy COM object could not be created.");
                }

                comRules = firewallPolicy.Rules;
                foreach (INetFwRule2 rule in comRules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    if (string.Equals(rule.Grouping, groupName, StringComparison.OrdinalIgnoreCase))
                    {
                        rulesInGroup.Add(rule);
                    }
                    else
                    {
                        ReleaseQuietly(rule);
                    }
                }

                foreach (var rule in rulesInGroup)
                {
                    try
                    {
                        if (rule.Enabled != isEnabled)
                        {
                            rule.Enabled = isEnabled;
                            changedCount++;
                        }
                    }
                    catch (COMException ex)
                    {
                        failures.Add(new FirewallRuleOperationFailure(SafeRuleName(rule), ex));
                    }
                }

                return FirewallRuleQueryResult<int>.Success(changedCount, failures);
            }
            finally
            {
                foreach (var rule in rulesInGroup)
                {
                    ReleaseQuietly(rule);
                }

                ReleaseQuietly(comRules);
                ReleaseQuietly(firewallPolicy);
            }
        });

    /// <summary>
    /// Visits every rule once. Each rule is released right after it is visited, and rules that were
    /// never reached because the loop aborted are released in the outer finally. A COMException on
    /// a single rule is recorded and the loop continues (best-effort).
    /// </summary>
    private static void ForEachRule(Action<INetFwRule2> visit, List<FirewallRuleOperationFailure> failures)
    {
        var allRules = FirewallRuleService.GetAllRules();
        int index = 0;
        try
        {
            for (; index < allRules.Count; index++)
            {
                var rule = allRules[index];
                if (rule == null)
                {
                    continue;
                }

                try
                {
                    visit(rule);
                }
                catch (COMException ex)
                {
                    failures.Add(new FirewallRuleOperationFailure(SafeRuleName(rule), ex));
                }
                finally
                {
                    ReleaseQuietly(rule);
                }
            }
        }
        finally
        {
            for (int i = index + 1; i < allRules.Count; i++)
            {
                ReleaseQuietly(allRules[i]);
            }
        }
    }

    private static FirewallRuleQueryResult<T> Execute<T>(
        string operationName,
        Func<FirewallRuleQueryResult<T>> operation)
    {
        try
        {
            return operation();
        }
        catch (COMException ex)
        {
            return FirewallRuleQueryResult<T>.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            return FirewallRuleQueryResult<T>.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            return FirewallRuleQueryResult<T>.Failure(
                $"{operationName} failed: {ex.Message}", ex);
        }
    }

    private static string SafeRuleName(INetFwRule2 rule)
    {
        try
        {
            return rule.Name ?? string.Empty;
        }
        catch (COMException)
        {
            return "<unknown>";
        }
    }

    private static void ReleaseQuietly(object? comObject)
    {
        if (comObject == null)
        {
            return;
        }

        try
        {
            Marshal.ReleaseComObject(comObject);
        }
        catch (ArgumentException)
        {
            // Not an RCW (already released elsewhere) - nothing left to free.
        }
    }
}
