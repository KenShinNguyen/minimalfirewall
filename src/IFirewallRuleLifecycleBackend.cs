using System.Collections.Generic;

namespace MinimalFirewall;

public sealed class FirewallRuleLifecycleOperationResult
{
    public bool Succeeded { get; init; }
    public string? Error { get; init; }

    public static FirewallRuleLifecycleOperationResult Success() =>
        new() { Succeeded = true };

    public static FirewallRuleLifecycleOperationResult Failure(string error) =>
        new() { Succeeded = false, Error = error };
}

public interface IFirewallRuleLifecycleBackend
{
    FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths);
    FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames);
    FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames);
    FirewallRuleLifecycleOperationResult DeleteByDescription(string description);
    FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName);
    FirewallRuleLifecycleOperationResult DeleteAllMfwRules();
    FirewallRuleLifecycleOperationResult EnableByName(string ruleName);
    FirewallRuleLifecycleOperationResult DisableByName(string ruleName);
}
