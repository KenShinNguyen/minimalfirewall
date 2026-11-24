using System.Runtime.InteropServices;
using NetFwTypeLib;

namespace MinimalFirewall;

public sealed class WindowsSystemFirewallRuleBackend : ISystemFirewallRuleBackend
{
    public SystemFirewallRuleOperationResult EnsureRule(SystemFirewallRuleDefinition definition)
    {
        try
        {
            using FirewallRuleHandle? handle = FirewallRuleService.GetRuleHandleByName(definition.Name);

            if (handle != null)
            {
                if (!handle.Rule.Enabled)
                {
                    handle.Rule.Enabled = true;
                }

                return SystemFirewallRuleOperationResult.Success();
            }

            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
            if (ruleType == null)
            {
                return SystemFirewallRuleOperationResult.Failure(
                    "Could not load HNetCfg.FWRule type.");
            }

            var rule = (INetFwRule2)Activator.CreateInstance(ruleType)!;
            rule.Name = definition.Name;
            rule.Description = definition.Description;
            rule.Direction = SystemFirewallRuleMapper.ToComDirection(definition.Direction);
            rule.Action = SystemFirewallRuleMapper.ToComAction(definition.Action);
            rule.Grouping = MFWConstants.MainRuleGroup;
            rule.Enabled = SystemFirewallRuleMapper.ToComEnabled(definition.Enabled);
            rule.InterfaceTypes = "All";
            rule.Protocol = SystemFirewallRuleMapper.ToComProtocol(definition.Protocol);

            if (definition.Protocol is SystemFirewallRuleProtocol.Tcp or SystemFirewallRuleProtocol.Udp)
            {
                rule.RemotePorts = definition.RemotePorts;
                rule.LocalPorts = definition.LocalPorts;
            }

            if (!string.IsNullOrEmpty(definition.ApplicationName))
            {
                rule.ApplicationName = definition.ApplicationName;
            }

            if (!string.IsNullOrEmpty(definition.ServiceName))
            {
                rule.serviceName = definition.ServiceName;
            }

            FirewallRuleService.CreateRule(rule);
            return SystemFirewallRuleOperationResult.Success();
        }
        catch (COMException ex)
        {
            return SystemFirewallRuleOperationResult.Failure(ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return SystemFirewallRuleOperationResult.Failure(ex.Message);
        }
    }

    public SystemFirewallRuleOperationResult RemoveRule(string ruleName)
    {
        try
        {
            using FirewallRuleHandle? handle = FirewallRuleService.GetRuleHandleByName(ruleName);
            if (handle == null)
            {
                return SystemFirewallRuleOperationResult.Success();
            }

            FirewallRuleService.DeleteRulesByName([ruleName]);
            return SystemFirewallRuleOperationResult.Success();
        }
        catch (COMException ex)
        {
            return SystemFirewallRuleOperationResult.Failure(ex.Message);
        }
    }
}

internal static class SystemFirewallRuleMapper
{
    public static NET_FW_RULE_DIRECTION_ ToComDirection(SystemFirewallRuleDirection direction)
        => direction switch
        {
            SystemFirewallRuleDirection.Outbound =>
                NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT,
            _ => throw new ArgumentOutOfRangeException(nameof(direction), direction, "Unsupported system rule direction.")
        };

    public static NET_FW_ACTION_ ToComAction(SystemFirewallRuleAction action)
        => action switch
        {
            SystemFirewallRuleAction.Allow =>
                NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported system rule action.")
        };

    public static int ToComProtocol(SystemFirewallRuleProtocol protocol)
        => protocol switch
        {
            SystemFirewallRuleProtocol.Any => 256,
            SystemFirewallRuleProtocol.Tcp => 6,
            SystemFirewallRuleProtocol.Udp => 17,
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unsupported system rule protocol.")
        };

    public static bool ToComEnabled(bool enabled)
        => enabled switch
        {
            true => true,
            false => false
        };
}
