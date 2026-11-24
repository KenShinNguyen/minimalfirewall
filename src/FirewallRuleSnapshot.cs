namespace MinimalFirewall;

/// <summary>
/// COM-free snapshot of the Windows Firewall rule fields consumed by the application.
/// Values are copied while the COM object is still owned by the Windows backend.
/// </summary>
public sealed record FirewallRuleSnapshot(
    string Name,
    string Description,
    bool IsEnabled,
    int Direction,
    bool IsAllow,
    int Protocol,
    string ApplicationName,
    string ServiceName,
    string LocalPorts,
    string RemotePorts,
    string LocalAddresses,
    string RemoteAddresses,
    int Profiles,
    string Grouping,
    string InterfaceTypes,
    string IcmpTypesAndCodes);
