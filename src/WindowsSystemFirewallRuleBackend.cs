using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using NetFwTypeLib;

namespace MinimalFirewall;

public sealed class WindowsSystemFirewallRuleBackend : ISystemFirewallRuleBackend
{
    private readonly IFirewallRuleLifecycleBackend _lifecycleBackend;
    private readonly IFirewallRuleCreationBackend _creationBackend;

    public WindowsSystemFirewallRuleBackend(
        IFirewallRuleLifecycleBackend? lifecycleBackend = null,
        IFirewallRuleCreationBackend? creationBackend = null)
    {
        _lifecycleBackend = lifecycleBackend ?? new WindowsFirewallRuleLifecycleBackend();
        _creationBackend = creationBackend ?? new WindowsFirewallRuleCreationBackend();
    }

    public SystemFirewallRuleOperationResult EnsureRule(SystemFirewallRuleDefinition definition)
    {
        try
        {
            if (RuleExistsAndEnabled(definition.Name))
            {
                return SystemFirewallRuleOperationResult.Success();
            }

            var creationResult = _creationBackend.CreateRule(
                new FirewallRuleCreationDefinition(
                    definition.Name,
                    definition.Description,
                    definition.Enabled,
                    MFWConstants.MainRuleGroup,
                    (int)definition.Protocol,
                    definition.Action == SystemFirewallRuleAction.Allow
                        ? FirewallRuleCreationAction.Allow
                        : FirewallRuleCreationAction.Block,
                    definition.Direction == SystemFirewallRuleDirection.Outbound
                        ? FirewallRuleCreationDirection.Outgoing
                        : FirewallRuleCreationDirection.Incoming,
                    definition.ServiceName,
                    definition.ApplicationName,
                    definition.LocalPorts,
                    definition.RemotePorts,
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    FirewallRuleCreationProfile.All,
                    "All"));

            return creationResult.Succeeded
                ? SystemFirewallRuleOperationResult.Success()
                : SystemFirewallRuleOperationResult.Failure(
                    creationResult.Error ?? "Failed to create firewall rule.");
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
            if (!RuleExists(ruleName))
            {
                return SystemFirewallRuleOperationResult.Success();
            }

            var result = _lifecycleBackend.DeleteByName([ruleName]);
            return result.Succeeded
                ? SystemFirewallRuleOperationResult.Success()
                : SystemFirewallRuleOperationResult.Failure(result.Error ?? "Failed to delete firewall rule.");
        }
        catch (COMException ex)
        {
            return SystemFirewallRuleOperationResult.Failure(ex.Message);
        }
    }

    private static bool RuleExists(string ruleName)
    {
        return GetRuleByName(ruleName) != null;
    }

    private static bool RuleExistsAndEnabled(string ruleName)
    {
        INetFwRule2? rule = GetRuleByName(ruleName);
        if (rule == null)
        {
            return false;
        }

        try
        {
            if (!rule.Enabled)
            {
                rule.Enabled = true;
            }

            return true;
        }
        finally
        {
            Marshal.ReleaseComObject(rule);
        }
    }

    private static INetFwRule2? GetRuleByName(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return null;
        }

        INetFwPolicy2? firewallPolicy = null;
        INetFwRules? rulesCollection = null;

        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (policyType == null)
            {
                return null;
            }

            firewallPolicy = (INetFwPolicy2?)Activator.CreateInstance(policyType);
            if (firewallPolicy == null)
            {
                return null;
            }

            rulesCollection = firewallPolicy.Rules;
            if (rulesCollection == null)
            {
                return null;
            }

            try
            {
                return rulesCollection.Item(ruleName) as INetFwRule2;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] GetRuleByName ('{ruleName}'): COM error. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                return null;
            }
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
