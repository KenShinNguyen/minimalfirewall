namespace MinimalFirewall;

/// <summary>
/// Boundary for updating mutable firewall-rule properties without exposing Windows Firewall COM types.
/// </summary>
public interface IFirewallRuleUpdateBackend
{
    void UpdateRemoteAddresses(string ruleName, string newRemoteAddresses);
}
