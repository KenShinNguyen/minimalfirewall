using System;
using System.Collections.Generic;

namespace MinimalFirewall;

/// <summary>Plain snapshot of a Windows Firewall rule. Contains no COM types.</summary>
public sealed record FirewallRuleSummary(
    string Name,
    string ApplicationName,
    string Grouping,
    int Protocol,
    bool IsBlock,
    string LocalPorts,
    string RemotePorts);

/// <summary>A single rule that could not be read or changed while a batch operation kept going.</summary>
public sealed record FirewallRuleOperationFailure(string RuleName, Exception Exception);

public sealed class FirewallRuleQueryResult<T>
{
    public bool Succeeded { get; init; }
    public T? Value { get; init; }
    public string? Error { get; init; }
    public int? HResult { get; init; }
    public Exception? Exception { get; init; }
    public IReadOnlyList<FirewallRuleOperationFailure> RuleFailures { get; init; } = [];

    public static FirewallRuleQueryResult<T> Success(
        T value,
        IReadOnlyList<FirewallRuleOperationFailure>? ruleFailures = null) =>
        new()
        {
            Succeeded = true,
            Value = value,
            RuleFailures = ruleFailures ?? []
        };

    public static FirewallRuleQueryResult<T> Failure(string error, Exception? exception = null) =>
        new()
        {
            Succeeded = false,
            Error = error,
            HResult = exception?.HResult,
            Exception = exception
        };
}

public interface IFirewallRuleQueryBackend
{
    /// <summary>
    /// Returns every rule that belongs to a Minimal Firewall group (see <see cref="MfwRuleGroups.IsMfwGroup"/>).
    /// Rules whose properties cannot be read are skipped and reported in <c>RuleFailures</c>.
    /// </summary>
    FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules();

    /// <summary>
    /// Enables every disabled Minimal Firewall rule (see <see cref="MfwRuleGroups.IsReenableTargetGroup"/>).
    /// A rule that fails is reported in <c>RuleFailures</c> and the remaining rules are still processed.
    /// </summary>
    FirewallRuleQueryResult<int> EnableMfwRules();

    /// <summary>
    /// Sets the enabled state of every rule in the named group.
    /// A rule that fails is reported in <c>RuleFailures</c> and the remaining rules are still processed.
    /// </summary>
    FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled);
}

public static class MfwRuleGroups
{
    /// <summary>Whether a rule grouping identifies a Minimal Firewall rule.</summary>
    public static bool IsMfwGroup(string? grouping)
    {
        if (string.IsNullOrEmpty(grouping))
        {
            return false;
        }

        return grouping.EndsWith(MFWConstants.MfwRuleSuffix, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(grouping, MFWConstants.MainRuleGroup, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(grouping, MFWConstants.WildcardRuleGroup, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Grouping test used when re-enabling rules after lockdown. It also accepts the two legacy
    /// group names without the " - MFW" suffix, exactly as the original ReenableMfwRules did.
    /// </summary>
    public static bool IsReenableTargetGroup(string? grouping)
    {
        if (string.IsNullOrEmpty(grouping))
        {
            return false;
        }

        return grouping.EndsWith(MFWConstants.MfwRuleSuffix, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(grouping, "Minimal Firewall", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(grouping, "Minimal Firewall (Wildcard)", StringComparison.OrdinalIgnoreCase);
    }
}
