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
/// Pure C# validation/normalization helpers for the rule-creation boundary.
/// Windows COM enum mapping stays inside WindowsFirewallRuleCreationBackend.
/// </summary>
public static class FirewallRuleCreationMapper
{
    public static int MapActionValue(FirewallRuleCreationAction action) =>
        action switch
        {
            FirewallRuleCreationAction.Allow => 1,
            FirewallRuleCreationAction.Block => 0,
            _ => throw new ArgumentException($"Unsupported firewall action: {action}", nameof(action))
        };

    public static int MapDirectionValue(FirewallRuleCreationDirection direction) =>
        direction switch
        {
            FirewallRuleCreationDirection.Incoming => 1,
            FirewallRuleCreationDirection.Outgoing => 2,
            _ => throw new ArgumentException($"Unsupported firewall direction: {direction}", nameof(direction))
        };

    public static int MapProtocol(int protocol) =>
        protocol switch
        {
            1 => 1,
            2 => 2,
            6 => 6,
            17 => 17,
            58 => 58,
            256 => 256,
            _ when protocol >= 0 && protocol <= 255 => protocol,
            _ => throw new ArgumentException($"Unsupported firewall protocol: {protocol}", nameof(protocol))
        };

    public static int MapProfileMask(FirewallRuleCreationProfile profile)
    {
        if (profile == FirewallRuleCreationProfile.All)
        {
            return int.MaxValue;
        }

        var result = 0;

        if ((profile & FirewallRuleCreationProfile.Domain) != 0)
        {
            result |= 1;
        }

        if ((profile & FirewallRuleCreationProfile.Private) != 0)
        {
            result |= 2;
        }

        if ((profile & FirewallRuleCreationProfile.Public) != 0)
        {
            result |= 4;
        }

        return result == 0 ? int.MaxValue : result;
    }

    public static FirewallRuleCreationProfile ParseProfiles(string? profiles)
    {
        if (string.Equals(profiles?.Trim(), "All", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(profiles))
        {
            return FirewallRuleCreationProfile.All;
        }

        var result = FirewallRuleCreationProfile.None;
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
