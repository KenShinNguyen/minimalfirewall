using System;
using MinimalFirewall.TypedObjects;
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
    public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
        => Execute("query all firewall rules", () =>
        {
            var snapshots = new List<FirewallRuleSnapshot>();
            var failures = new List<FirewallRuleOperationFailure>();

            ForEachRule(rule =>
            {
                snapshots.Add(CreateSnapshot(rule));
            }, failures);

            return FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Success(snapshots, failures);
        });

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

    public FirewallRuleQueryResult<IReadOnlyList<string>> GetRuleNamesByPathAndDirection(string appPath, Directions direction)
        => Execute("query rule names by path and direction", () =>
        {
            if (string.IsNullOrEmpty(appPath))
            {
                return FirewallRuleQueryResult<IReadOnlyList<string>>.Success([]);
            }

            string normalizedAppPath = PathResolver.NormalizePath(appPath);
            var names = new List<string>();
            var failures = new List<FirewallRuleOperationFailure>();

            ForEachRule(rule =>
            {
                if (!string.IsNullOrEmpty(rule.ApplicationName) &&
                    string.Equals(PathResolver.NormalizePath(rule.ApplicationName), normalizedAppPath, StringComparison.OrdinalIgnoreCase) &&
                    (int)rule.Direction == (int)direction)
                {
                    names.Add(rule.Name ?? string.Empty);
                }
            }, failures);

            return FirewallRuleQueryResult<IReadOnlyList<string>>.Success(names, failures);
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
        if (FwPolicyType == null)
        {
            failures.Add(new FirewallRuleOperationFailure(
                "<policy>",
                new InvalidOperationException("Windows Firewall policy COM type is unavailable.")));
            return;
        }

        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? comRules = null;
        try
        {
            firewallPolicy = Activator.CreateInstance(FwPolicyType) as INetFwPolicy2;
            if (firewallPolicy == null)
            {
                failures.Add(new FirewallRuleOperationFailure(
                    "<policy>",
                    new InvalidOperationException("Windows Firewall policy COM object could not be created.")));
                return;
            }

            comRules = firewallPolicy.Rules;
            if (comRules == null)
            {
                return;
            }

            foreach (INetFwRule2 rule in comRules)
            {
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
        catch (COMException ex)
        {
            failures.Add(new FirewallRuleOperationFailure("<enumeration>", ex));
        }
        finally
        {
            ReleaseQuietly(comRules);
            ReleaseQuietly(firewallPolicy);
        }
    }

    internal static FirewallRuleSnapshot CreateSnapshot(INetFwRule2 rule)
        => new(
            rule.Name ?? string.Empty,
            rule.Description ?? string.Empty,
            rule.Enabled,
            (int)rule.Direction,
            rule.Action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            (int)rule.Protocol,
            rule.ApplicationName ?? string.Empty,
            rule.serviceName ?? string.Empty,
            rule.LocalPorts ?? string.Empty,
            rule.RemotePorts ?? string.Empty,
            rule.LocalAddresses ?? string.Empty,
            rule.RemoteAddresses ?? string.Empty,
            (int)rule.Profiles,
            rule.Grouping ?? string.Empty,
            rule.InterfaceTypes ?? string.Empty,
            rule.IcmpTypesAndCodes ?? string.Empty);

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
