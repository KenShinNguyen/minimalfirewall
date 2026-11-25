using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using NetFwTypeLib;

namespace MinimalFirewall;

public sealed class WindowsFirewallRuleGroupBackend : IFirewallRuleGroupBackend
{
    private static readonly Type? FwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    public FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>> GetGroups()
        => Execute("query firewall rule groups", () =>
        {
            if (FwPolicyType == null)
            {
                return FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>>.Failure(
                    "Windows Firewall policy COM type is unavailable.");
            }

            INetFwPolicy2? policy = null;
            INetFwRules? comRules = null;
            var groups = new Dictionary<string, GroupAccumulator>(StringComparer.OrdinalIgnoreCase);
            var failures = new List<FirewallRuleGroupOperationFailure>();

            try
            {
                policy = Activator.CreateInstance(FwPolicyType) as INetFwPolicy2;
                if (policy == null)
                {
                    return FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>>.Failure(
                        "Windows Firewall policy COM object could not be created.");
                }

                comRules = policy.Rules;

                foreach (INetFwRule2 rule in comRules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    try
                    {
                        string grouping = rule.Grouping;
                        if (string.IsNullOrEmpty(grouping) ||
                            !grouping.EndsWith(MFWConstants.MfwRuleSuffix, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (!groups.TryGetValue(grouping, out var accumulator))
                        {
                            accumulator = new GroupAccumulator();
                            groups[grouping] = accumulator;
                        }

                        accumulator.RuleCount++;
                        if (rule.Enabled)
                        {
                            accumulator.EnabledCount++;
                        }
                    }
                    catch (COMException ex)
                    {
                        failures.Add(new FirewallRuleGroupOperationFailure(SafeRuleName(rule), ex));
                    }
                    finally
                    {
                        ReleaseQuietly(rule);
                    }

                }

                var snapshots = new List<FirewallRuleGroupSnapshot>(groups.Count);
                foreach (var pair in groups)
                {
                    snapshots.Add(new FirewallRuleGroupSnapshot(
                        pair.Key,
                        pair.Value.RuleCount,
                        pair.Value.RuleCount > 0 && pair.Value.EnabledCount == pair.Value.RuleCount));
                }

                snapshots.Sort((left, right) =>
                    StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name));

                return FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>>.Success(
                    snapshots,
                    failures);
            }
            finally
            {
                ReleaseQuietly(comRules);
                ReleaseQuietly(policy);
            }
        });

    public FirewallRuleGroupResult<int> SetGroupEnabled(string groupName, bool isEnabled)
        => Execute("set firewall rule group enabled state", () =>
        {
            if (string.IsNullOrWhiteSpace(groupName))
            {
                return FirewallRuleGroupResult<int>.Failure("Firewall rule group name is required.");
            }

            if (FwPolicyType == null)
            {
                return FirewallRuleGroupResult<int>.Failure(
                    "Windows Firewall policy COM type is unavailable.");
            }

            INetFwPolicy2? policy = null;
            INetFwRules? comRules = null;
            var failures = new List<FirewallRuleGroupOperationFailure>();
            int changedCount = 0;

            try
            {
                policy = Activator.CreateInstance(FwPolicyType) as INetFwPolicy2;
                if (policy == null)
                {
                    return FirewallRuleGroupResult<int>.Failure(
                        "Windows Firewall policy COM object could not be created.");
                }

                comRules = policy.Rules;

                foreach (INetFwRule2 rule in comRules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    try
                    {
                        if (string.Equals(rule.Grouping, groupName, StringComparison.OrdinalIgnoreCase) &&
                            rule.Enabled != isEnabled)
                        {
                            rule.Enabled = isEnabled;
                            changedCount++;
                        }
                    }
                    catch (COMException ex)
                    {
                        failures.Add(new FirewallRuleGroupOperationFailure(SafeRuleName(rule), ex));
                    }
                    finally
                    {
                        ReleaseQuietly(rule);
                    }
                }

                return FirewallRuleGroupResult<int>.Success(changedCount, failures);
            }
            finally
            {
                ReleaseQuietly(comRules);
                ReleaseQuietly(policy);
            }
        });

    private static FirewallRuleGroupResult<T> Execute<T>(
        string operationName,
        Func<FirewallRuleGroupResult<T>> operation)
    {
        try
        {
            return operation();
        }
        catch (COMException ex)
        {
            return FirewallRuleGroupResult<T>.Failure(
                $"{operationName} failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}",
                ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            return FirewallRuleGroupResult<T>.Failure(
                $"{operationName} failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}",
                ex);
        }
        catch (InvalidOperationException ex)
        {
            return FirewallRuleGroupResult<T>.Failure(
                $"{operationName} failed: {ex.Message}",
                ex);
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
        }
    }

    private sealed class GroupAccumulator
    {
        public int RuleCount { get; set; }
        public int EnabledCount { get; set; }
    }
}
