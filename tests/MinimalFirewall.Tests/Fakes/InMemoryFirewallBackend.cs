using System;
using System.Collections.Generic;
using System.Linq;
using MinimalFirewall.TypedObjects;

namespace MinimalFirewall.Tests.Fakes;

/// <summary>
/// Stateful, in-memory implementation of the application-facing firewall backend contracts.
/// It deliberately contains no Windows Firewall or COM references.
/// </summary>
public sealed class InMemoryFirewallBackend :
    IFirewallBackend,
    ISystemFirewallRuleBackend,
    IFirewallRuleQueryBackend,
    IFirewallRuleLifecycleBackend,
    IFirewallRuleCreationBackend
{
    private readonly List<FirewallRuleSnapshot> _rules = [];
    private readonly List<string> _operations = [];

    public bool ThrowOnQuery { get; set; }
    public bool ThrowOnMutate { get; set; }
    public bool FailMutations { get; set; }
    public FirewallPolicyState PolicyState { get; set; } = FirewallPolicyState.Allow;

    public int SnapshotQueryCalls { get; private set; }
    public int SummaryQueryCalls { get; private set; }
    public IReadOnlyList<string> Operations => _operations.ToArray();
    public IReadOnlyList<FirewallRuleSnapshot> Rules => _rules.ToArray();

    public void Seed(params FirewallRuleSnapshot[] rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _rules.AddRange(rules);
    }

    public FirewallPolicyState GetDefaultOutboundState()
    {
        ThrowIfQueryingFails();
        return PolicyState;
    }

    public FirewallPolicyOperationResult SetDefaultOutboundAction(FirewallOutboundAction action)
    {
        Record("SetDefaultOutboundAction");
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return new FirewallPolicyOperationResult
            {
                RequestedAction = action,
                Succeeded = false,
                DiagnosticSummary = "Simulated policy mutation failure."
            };
        }

        PolicyState = action == FirewallOutboundAction.Block
            ? FirewallPolicyState.Block
            : FirewallPolicyState.Allow;

        return new FirewallPolicyOperationResult
        {
            RequestedAction = action,
            Succeeded = true
        };
    }

    public SystemFirewallRuleOperationResult EnsureRule(SystemFirewallRuleDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        Record($"EnsureSystemRule:{definition.Name}");
        ThrowIfMutationThrows();
        return FailMutations
            ? SystemFirewallRuleOperationResult.Failure("Simulated system rule failure.")
            : SystemFirewallRuleOperationResult.Success();
    }

    public SystemFirewallRuleOperationResult RemoveRule(string ruleName)
    {
        Record($"RemoveSystemRule:{ruleName}");
        ThrowIfMutationThrows();
        return FailMutations
            ? SystemFirewallRuleOperationResult.Failure("Simulated system rule failure.")
            : SystemFirewallRuleOperationResult.Success();
    }

    public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
    {
        SnapshotQueryCalls++;
        ThrowIfQueryingFails();
        return FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Success(_rules.ToArray());
    }

    public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules()
    {
        SummaryQueryCalls++;
        ThrowIfQueryingFails();

        IReadOnlyList<FirewallRuleSummary> result = _rules
            .Where(rule => MfwRuleGroups.IsMfwGroup(rule.Grouping))
            .Select(rule => new FirewallRuleSummary(
                rule.Name,
                rule.ApplicationName,
                rule.Grouping,
                rule.Protocol,
                !rule.IsAllow,
                rule.LocalPorts,
                rule.RemotePorts))
            .ToArray();

        return FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success(result);
    }

    public FirewallRuleQueryResult<int> EnableMfwRules()
    {
        Record("EnableMfwRules");
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return FirewallRuleQueryResult<int>.Failure("Simulated enable failure.");
        }

        int changed = 0;
        for (int index = 0; index < _rules.Count; index++)
        {
            if (MfwRuleGroups.IsReenableTargetGroup(_rules[index].Grouping) && !_rules[index].IsEnabled)
            {
                _rules[index] = _rules[index] with { IsEnabled = true };
                changed++;
            }
        }

        return FirewallRuleQueryResult<int>.Success(changed);
    }

    public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled)
    {
        Record($"SetGroupEnabled:{groupName}:{isEnabled}");
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return FirewallRuleQueryResult<int>.Failure("Simulated group mutation failure.");
        }

        int changed = 0;
        for (int index = 0; index < _rules.Count; index++)
        {
            if (string.Equals(_rules[index].Grouping, groupName, StringComparison.OrdinalIgnoreCase) &&
                _rules[index].IsEnabled != isEnabled)
            {
                _rules[index] = _rules[index] with { IsEnabled = isEnabled };
                changed++;
            }
        }

        return FirewallRuleQueryResult<int>.Success(changed);
    }

    public FirewallRuleQueryResult<IReadOnlyList<string>> GetRuleNamesByPathAndDirection(
        string appPath,
        Directions direction)
    {
        ThrowIfQueryingFails();

        IReadOnlyList<string> names = _rules
            .Where(rule =>
                string.Equals(rule.ApplicationName, appPath, StringComparison.OrdinalIgnoreCase) &&
                (((Directions)rule.Direction) & direction) == direction)
            .Select(rule => rule.Name)
            .ToArray();

        return FirewallRuleQueryResult<IReadOnlyList<string>>.Success(names);
    }

    public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths)
        => DeleteWhere("DeleteByPath", rule => appPaths.Contains(rule.ApplicationName, StringComparer.OrdinalIgnoreCase));

    public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames)
        => DeleteWhere("DeleteUwp", rule => packageFamilyNames.Contains(rule.ApplicationName, StringComparer.OrdinalIgnoreCase));

    public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames)
        => DeleteWhere("DeleteByName", rule => ruleNames.Contains(rule.Name, StringComparer.OrdinalIgnoreCase));

    public FirewallRuleLifecycleOperationResult DeleteByDescription(string description)
        => DeleteWhere("DeleteByDescription", rule => string.Equals(rule.Description, description, StringComparison.OrdinalIgnoreCase));

    public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName)
        => DeleteWhere("DeleteByGroup", rule => string.Equals(rule.Grouping, groupName, StringComparison.OrdinalIgnoreCase));

    public FirewallRuleLifecycleOperationResult DeleteAllMfwRules()
        => DeleteWhere("DeleteAllMfwRules", rule => MfwRuleGroups.IsMfwGroup(rule.Grouping));

    public FirewallRuleLifecycleOperationResult EnableByName(string ruleName)
        => SetEnabledByName("EnableByName", ruleName, true);

    public FirewallRuleLifecycleOperationResult DisableByName(string ruleName)
        => SetEnabledByName("DisableByName", ruleName, false);

    public FirewallRuleLifecycleOperationResult DeleteConflictingServiceRules(
        string serviceName,
        Actions newAction,
        Directions newDirection)
        => DeleteWhere(
            "DeleteConflictingServiceRules",
            rule => string.Equals(rule.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase) &&
                    (((Directions)rule.Direction) & newDirection) != 0 &&
                    rule.IsAllow != (newAction == Actions.Allow));

    public FirewallRuleCreationResult CreateRule(FirewallRuleCreationDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        Record($"CreateRule:{definition.Name}");
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return FirewallRuleCreationResult.Failure("Simulated rule creation failure.");
        }

        _rules.Add(new FirewallRuleSnapshot(
            definition.Name,
            definition.Description,
            definition.Enabled,
            (int)definition.Direction,
            definition.Action == FirewallRuleCreationAction.Allow,
            definition.Protocol,
            definition.ApplicationName,
            definition.ServiceName,
            definition.LocalPorts,
            definition.RemotePorts,
            definition.LocalAddresses,
            definition.RemoteAddresses,
            FirewallRuleCreationMapper.MapProfileMask(definition.Profiles),
            definition.Grouping,
            definition.InterfaceTypes,
            definition.IcmpTypesAndCodes));

        return FirewallRuleCreationResult.Success();
    }

    private FirewallRuleLifecycleOperationResult DeleteWhere(
        string operation,
        Func<FirewallRuleSnapshot, bool> predicate)
    {
        Record(operation);
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return FirewallRuleLifecycleOperationResult.Failure("Simulated lifecycle failure.");
        }

        _rules.RemoveAll(rule => predicate(rule));
        return FirewallRuleLifecycleOperationResult.Success();
    }

    private FirewallRuleLifecycleOperationResult SetEnabledByName(
        string operation,
        string ruleName,
        bool enabled)
    {
        Record($"{operation}:{ruleName}");
        ThrowIfMutationThrows();
        if (FailMutations)
        {
            return FirewallRuleLifecycleOperationResult.Failure("Simulated lifecycle failure.");
        }

        for (int index = 0; index < _rules.Count; index++)
        {
            if (string.Equals(_rules[index].Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                _rules[index] = _rules[index] with { IsEnabled = enabled };
            }
        }

        return FirewallRuleLifecycleOperationResult.Success();
    }

    private void Record(string operation) => _operations.Add(operation);

    private void ThrowIfQueryingFails()
    {
        if (ThrowOnQuery)
        {
            throw new InvalidOperationException("Simulated firewall query failure.");
        }
    }

    private void ThrowIfMutationThrows()
    {
        if (ThrowOnMutate)
        {
            throw new InvalidOperationException("Simulated firewall mutation failure.");
        }
    }
}
