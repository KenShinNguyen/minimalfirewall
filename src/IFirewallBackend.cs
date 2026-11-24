namespace MinimalFirewall;

public interface IFirewallBackend
{
    FirewallPolicyState GetDefaultOutboundState();

    FirewallPolicyOperationResult SetDefaultOutboundAction(FirewallOutboundAction action);
}
