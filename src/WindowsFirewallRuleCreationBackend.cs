using NetFwTypeLib;
using System;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

public sealed class WindowsFirewallRuleCreationBackend : IFirewallRuleCreationBackend
{
    private static readonly Type? FwRuleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
    private static readonly Type? FwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");

    public FirewallRuleCreationResult CreateRule(FirewallRuleCreationDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        INetFwRule2? firewallRule = null;
        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? rulesCollection = null;

        try
        {
            if (FwRuleType is null || FwPolicyType is null)
            {
                throw new InvalidOperationException("Windows Firewall COM types could not be loaded.");
            }

            firewallRule = (INetFwRule2)Activator.CreateInstance(FwRuleType)!;
            firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicyType)!;
            rulesCollection = firewallPolicy.Rules
                ?? throw new InvalidOperationException("Windows Firewall rules collection could not be loaded.");

            // Preserve the COM-sensitive ordering from the legacy implementation:
            // Protocol MUST be assigned before LocalPorts/RemotePorts/IcmpTypesAndCodes.
            firewallRule.Name = definition.Name;
            firewallRule.Description = definition.Description;
            firewallRule.Enabled = definition.Enabled;
            firewallRule.Grouping = definition.Grouping;

            firewallRule.Protocol = MapProtocol(definition.Protocol);
            firewallRule.Action = MapAction(definition.Action);
            firewallRule.Direction = MapDirection(definition.Direction);

            if (!string.IsNullOrWhiteSpace(definition.ServiceName))
            {
                firewallRule.serviceName = definition.ServiceName;
            }

            firewallRule.ApplicationName = string.IsNullOrWhiteSpace(definition.ApplicationName)
                ? null
                : definition.ApplicationName;

            if (definition.Protocol is 6 or 17)
            {
                firewallRule.LocalPorts = string.IsNullOrEmpty(definition.LocalPorts)
                    ? "*"
                    : definition.LocalPorts;
                firewallRule.RemotePorts = string.IsNullOrEmpty(definition.RemotePorts)
                    ? "*"
                    : definition.RemotePorts;
            }

            firewallRule.LocalAddresses = string.IsNullOrEmpty(definition.LocalAddresses)
                ? "*"
                : definition.LocalAddresses;
            firewallRule.RemoteAddresses = string.IsNullOrEmpty(definition.RemoteAddresses)
                ? "*"
                : definition.RemoteAddresses;

            if (definition.Protocol is 1 or 58)
            {
                firewallRule.IcmpTypesAndCodes = string.IsNullOrWhiteSpace(definition.IcmpTypesAndCodes)
                    ? "*"
                    : definition.IcmpTypesAndCodes;
            }

            firewallRule.Profiles = MapProfiles(definition.Profiles);

            try
            {
                firewallRule.InterfaceTypes = string.IsNullOrWhiteSpace(definition.InterfaceTypes)
                    ? "All"
                    : definition.InterfaceTypes;
            }
            catch (Exception)
            {
                // Preserve legacy behavior: InterfaceTypes is best-effort and falls back to All.
                firewallRule.InterfaceTypes = "All";
            }

            rulesCollection.Add(firewallRule);
            return FirewallRuleCreationResult.Success();
        }
        catch (COMException ex)
        {
            return FirewallRuleCreationResult.Failure(
                $"Create firewall rule failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}",
                ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            return FirewallRuleCreationResult.Failure(
                $"Create firewall rule failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)} Details: {ex.Message}",
                ex);
        }
        catch (InvalidOperationException ex)
        {
            return FirewallRuleCreationResult.Failure(
                $"Create firewall rule failed: {ex.Message}",
                ex);
        }
        finally
        {
            if (rulesCollection != null)
            {
                Marshal.ReleaseComObject(rulesCollection);
            }

            if (firewallPolicy != null)
            {
                Marshal.ReleaseComObject(firewallPolicy);
            }

            if (firewallRule != null)
            {
                Marshal.ReleaseComObject(firewallRule);
            }
        }
    }

    private static NET_FW_ACTION_ MapAction(FirewallRuleCreationAction action) =>
        action switch
        {
            FirewallRuleCreationAction.Allow => NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            FirewallRuleCreationAction.Block => NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            _ => throw new ArgumentException($"Unsupported firewall action: {action}", nameof(action))
        };

    private static NET_FW_RULE_DIRECTION_ MapDirection(FirewallRuleCreationDirection direction) =>
        direction switch
        {
            FirewallRuleCreationDirection.Incoming => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN,
            FirewallRuleCreationDirection.Outgoing => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT,
            _ => throw new ArgumentException($"Unsupported firewall direction: {direction}", nameof(direction))
        };

    private static int MapProtocol(int protocol) =>
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

    private static int MapProfiles(FirewallRuleCreationProfile profiles)
    {
        if (profiles == FirewallRuleCreationProfile.All)
        {
            return int.MaxValue;
        }

        var mapped = 0;

        if ((profiles & FirewallRuleCreationProfile.Domain) != 0)
        {
            mapped |= 1;
        }

        if ((profiles & FirewallRuleCreationProfile.Private) != 0)
        {
            mapped |= 2;
        }

        if ((profiles & FirewallRuleCreationProfile.Public) != 0)
        {
            mapped |= 4;
        }

        return mapped == 0 ? int.MaxValue : mapped;
    }
}
