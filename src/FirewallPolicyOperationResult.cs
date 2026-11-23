namespace MinimalFirewall;

public sealed class FirewallPolicyOperationResult
{
    public FirewallOutboundAction RequestedAction { get; init; }

    public bool Succeeded { get; init; }

    public bool RolledBack { get; init; }

    public bool RollbackIncomplete { get; init; }

    public string? DiagnosticSummary { get; init; }
}
