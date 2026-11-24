using System;
using MinimalFirewall.TypedObjects;

namespace MinimalFirewall;

public enum FirewallRuleCreationAction
{
    Block = 0,
    Allow = 1
}

public enum FirewallRuleCreationDirection
{
    Incoming = 1,
    Outgoing = 2
}

[Flags]
public enum FirewallRuleCreationProfile
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = int.MaxValue
}

/// <summary>
/// Pure C# rule definition used at the rule-creation boundary.
/// This type intentionally contains no NetFwTypeLib COM types.
/// </summary>
public sealed record FirewallRuleCreationDefinition(
    string Name,
    string Description,
    bool Enabled,
    string Grouping,
    int Protocol,
    FirewallRuleCreationAction Action,
    FirewallRuleCreationDirection Direction,
    string ServiceName,
    string ApplicationName,
    string LocalPorts,
    string RemotePorts,
    string LocalAddresses,
    string RemoteAddresses,
    string IcmpTypesAndCodes,
    FirewallRuleCreationProfile Profiles,
    string InterfaceTypes);

public sealed class FirewallRuleCreationResult
{
    public bool Succeeded { get; init; }
    public string? Error { get; init; }
    public int? HResult { get; init; }
    public Exception? Exception { get; init; }

    public static FirewallRuleCreationResult Success() => new() { Succeeded = true };

    public static FirewallRuleCreationResult Failure(string error, Exception? exception = null) =>
        new()
        {
            Succeeded = false,
            Error = error,
            HResult = exception?.HResult,
            Exception = exception
        };
}

public interface IFirewallRuleCreationBackend
{
    FirewallRuleCreationResult CreateRule(FirewallRuleCreationDefinition definition);
}

/// <summary>
/// Maps the pure C# rule model to the exact Windows Firewall values used by the COM backend.
/// Kept public so the mapping can be locked by unit tests without instantiating COM.
/// </summary>
public static class FirewallRuleCreationMapper
{
    public static NET_FW_ACTION_ MapAction(FirewallRuleCreationAction action) =>
        action switch
        {
            FirewallRuleCreationAction.Allow => NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            FirewallRuleCreationAction.Block => NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            _ => throw new ArgumentException($"Unsupported firewall action: {action}", nameof(action))
        };

    public static NET_FW_RULE_DIRECTION_ MapDirection(FirewallRuleCreationDirection direction) =>
        direction switch
        {
            FirewallRuleCreationDirection.Incoming => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN,
            FirewallRuleCreationDirection.Outgoing => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT,
            _ => throw new ArgumentException($"Unsupported firewall direction: {direction}", nameof(direction))
        };

    public static int MapProtocol(int protocol) =>
        protocol switch
        {
            1 => 1,   // ICMPv4
            2 => 2,   // IGMP
            6 => 6,   // TCP
            17 => 17, // UDP
            58 => 58, // ICMPv6
            256 => 256, // Any
            _ when protocol >= 0 && protocol <= 255 => protocol,
            _ => throw new ArgumentException($"Unsupported firewall protocol: {protocol}", nameof(protocol))
        };

    public static NET_FW_PROFILE_TYPE2_ MapProfileMask(FirewallRuleCreationProfile profile)
    {
        if (profile == FirewallRuleCreationProfile.All)
        {
            return NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
        }

        NET_FW_PROFILE_TYPE2_ result = 0;

        if ((profile & FirewallRuleCreationProfile.Domain) != 0)
        {
            result |= NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;
        }

        if ((profile & FirewallRuleCreationProfile.Private) != 0)
        {
            result |= NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
        }

        if ((profile & FirewallRuleCreationProfile.Public) != 0)
        {
            result |= NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
        }

        return result == 0
            ? NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL
            : result;
    }

    public static FirewallRuleCreationProfile ParseProfiles(string? profiles)
    {
        if (string.Equals(profiles?.Trim(), "All", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(profiles))
        {
            return FirewallRuleCreationProfile.All;
        }

        FirewallRuleCreationProfile result = FirewallRuleCreationProfile.None;
        foreach (var token in profiles.Split([',', '|', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            result |= token switch
            {
                var value when string.Equals(value, "Domain", StringComparison.OrdinalIgnoreCase) => FirewallRuleCreationProfile.Domain,
                var value when string.Equals(value, "Private", StringComparison.OrdinalIgnoreCase) => FirewallRuleCreationProfile.Private,
                var value when string.Equals(value, "Public", StringComparison.OrdinalIgnoreCase) => FirewallRuleCreationProfile.Public,
                var value when string.Equals(value, "All", StringComparison.OrdinalIgnoreCase) => FirewallRuleCreationProfile.All,
                _ => throw new ArgumentException($"Unsupported firewall profile: {token}", nameof(profiles))
            };
        }

        return result == FirewallRuleCreationProfile.None
            ? FirewallRuleCreationProfile.All
            : result;
    }

    public static FirewallRuleCreationDefinition FromViewModel(
        AdvancedRuleViewModel vm,
        string? interfaceTypes,
        string? icmpTypesAndCodes)
    {
        ArgumentNullException.ThrowIfNull(vm);

        return new FirewallRuleCreationDefinition(
            vm.Name,
            vm.Description,
            vm.IsEnabled,
            vm.Grouping,
            MapProtocol(vm.Protocol),
            vm.Status == "Allow"
                ? FirewallRuleCreationAction.Allow
                : FirewallRuleCreationAction.Block,
            vm.Direction switch
            {
                Directions.Incoming => FirewallRuleCreationDirection.Incoming,
                Directions.Outgoing => FirewallRuleCreationDirection.Outgoing,
                _ => throw new ArgumentException($"Advanced rule must have exactly one direction: {vm.Direction}", nameof(vm))
            },
            vm.ServiceName ?? string.Empty,
            vm.ApplicationName ?? string.Empty,
            vm.LocalPorts ?? string.Empty,
            vm.RemotePorts ?? string.Empty,
            vm.LocalAddresses ?? string.Empty,
            vm.RemoteAddresses ?? string.Empty,
            icmpTypesAndCodes ?? vm.IcmpTypesAndCodes ?? string.Empty,
            ParseProfiles(vm.Profiles),
            string.IsNullOrWhiteSpace(interfaceTypes) ? "All" : interfaceTypes);
    }
}
