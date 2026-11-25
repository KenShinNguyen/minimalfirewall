using NetFwTypeLib;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

/// <summary>
/// Windows Firewall implementation of policy administration.
/// All NetFwTypeLib COM ownership stays inside this class.
/// </summary>
public sealed class WindowsFirewallPolicyAdminBackend : IFirewallPolicyAdminBackend
{
    public FirewallPolicyAdminResult ResetFirewall()
    {
        INetFwMgr? fwMgr = null;

        try
        {
            var fwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr");
            if (fwMgrType == null)
            {
                return FirewallPolicyAdminResult.Failure(
                    "Windows Firewall policy manager COM class is unavailable.");
            }

            fwMgr = (INetFwMgr?)Activator.CreateInstance(fwMgrType);
            if (fwMgr == null)
            {
                return FirewallPolicyAdminResult.Failure(
                    "Windows Firewall policy manager could not be created.");
            }

            fwMgr.RestoreDefaults();
            Debug.WriteLine("[AdminTask] Firewall reset to defaults using COM interface.");
            return FirewallPolicyAdminResult.Success();
        }
        catch (COMException ex)
        {
            Debug.WriteLine($"[AdminTask ERROR] Firewall reset COM operation failed: {ex.Message}");
            return FirewallPolicyAdminResult.Failure(
                $"Windows Firewall reset failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)}",
                ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            Debug.WriteLine($"[AdminTask ERROR] Firewall reset access denied: {ex.Message}");
            return FirewallPolicyAdminResult.Failure(
                $"Windows Firewall reset failed. {FirewallRuleUpdateErrorMapper.DescribeHResult(ex.HResult)}",
                ex);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AdminTask ERROR] Firewall reset failed: {ex.Message}");
            return FirewallPolicyAdminResult.Failure(
                "Windows Firewall reset failed.",
                ex);
        }
        finally
        {
            if (fwMgr != null && Marshal.IsComObject(fwMgr))
            {
                Marshal.ReleaseComObject(fwMgr);
            }
        }
    }
}
