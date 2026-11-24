using System;
using System.Collections.Generic;

namespace MinimalFirewall;

public sealed record FirewallRuleGroupSnapshot(
    string Name,
    int RuleCount,
    bool IsEnabled);

public sealed record FirewallRuleGroupOperationFailure(
    string RuleName,
    Exception Exception);

public sealed class FirewallRuleGroupResult<T>
{
    public bool Succeeded { get; init; }
    public T? Value { get; init; }
    public string? Error { get; init; }
    public int? HResult { get; init; }
    public Exception? Exception { get; init; }
    public IReadOnlyList<FirewallRuleGroupOperationFailure> RuleFailures { get; init; } = [];

    public static FirewallRuleGroupResult<T> Success(
        T value,
        IReadOnlyList<FirewallRuleGroupOperationFailure>? ruleFailures = null) =>
        new()
        {
            Succeeded = true,
            Value = value,
            RuleFailures = ruleFailures ?? []
        };

    public static FirewallRuleGroupResult<T> Failure(
        string error,
        Exception? exception = null) =>
        new()
        {
            Succeeded = false,
            Error = error,
            HResult = exception?.HResult,
            Exception = exception
        };
}

public interface IFirewallRuleGroupBackend
{
    FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>> GetGroups();

    FirewallRuleGroupResult<int> SetGroupEnabled(string groupName, bool isEnabled);
}
