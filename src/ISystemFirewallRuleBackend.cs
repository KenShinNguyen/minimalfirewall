namespace MinimalFirewall;

public enum SystemFirewallRuleDirection
{
    Outbound
}

public enum SystemFirewallRuleAction
{
    Allow
}

public enum SystemFirewallRuleProtocol
{
    Any = 256,
    Tcp = 6,
    Udp = 17
}

public sealed record SystemFirewallRuleDefinition(
    string Name,
    string Description,
    string ApplicationName,
    string ServiceName,
    SystemFirewallRuleDirection Direction,
    SystemFirewallRuleAction Action,
    SystemFirewallRuleProtocol Protocol,
    string RemotePorts,
    string LocalPorts,
    bool Enabled);

public sealed class SystemFirewallRuleOperationResult
{
    public bool Succeeded { get; init; }
    public string? Error { get; init; }

    public static SystemFirewallRuleOperationResult Success() => new() { Succeeded = true };

    public static SystemFirewallRuleOperationResult Failure(string error) =>
        new() { Succeeded = false, Error = error };
}

public interface ISystemFirewallRuleBackend
{
    SystemFirewallRuleOperationResult EnsureRule(SystemFirewallRuleDefinition definition);
    SystemFirewallRuleOperationResult RemoveRule(string ruleName);
}
