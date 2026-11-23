namespace MinimalFirewall;

public sealed class FirewallPolicyOperationResult
{
    public FirewallOutboundAction RequestedAction { get; init; }

    public bool Succeeded { get; init; }
}
