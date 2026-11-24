using NetFwTypeLib;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall
{
    public class FirewallRuleService
    {
        private const int HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS = unchecked((int)0x800700B7);
        private static readonly Lazy<Type?> _firewallPolicyType = new(() => Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

        public FirewallRuleService()
        {
        }

        private static INetFwPolicy2 GetLocalPolicy()
        {
            if (_firewallPolicyType.Value == null)
            {
                throw new InvalidOperationException("Firewall policy type could not be retrieved.");
            }
            return (INetFwPolicy2)Activator.CreateInstance(_firewallPolicyType.Value)!;
        }

                /// <summary>
        /// Looks up a rule and hands back a disposable handle, so the caller cannot forget the
        /// matching release. Prefer this over letting a raw COM interface escape the service.
        /// </summary>
        public static FirewallRuleHandle? GetRuleHandleByName(string name)
        {
            INetFwRule2? rule = GetRuleByName(name);
            return rule == null ? null : new FirewallRuleHandle(rule);
        }

        private static INetFwRule2? GetRuleByName(string name)
        {
            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy == null)
            {
                return null;
            }

            INetFwRules? rulesCollection = null;
            try
            {
                rulesCollection = firewallPolicy.Rules;
                if (rulesCollection.Item(name) is INetFwRule2 rule)
                {
                    return rule;
                }
                return null;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] GetRuleByName ('{name}'): COM error. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                return null;
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

        /// <summary>
        /// Applies <paramref name="action"/> to every firewall profile as one unit: each write is
        /// read back to confirm it took effect, and if any profile fails the profiles that already
        /// changed are restored to their previous action. A partial application is reported as a
        /// failure, so a caller can never tell the user they are protected when only some profiles
        /// were actually updated.
        /// </summary>
        /// <summary>
        /// Reads the default outbound action of the active profile as a tri-state.
        /// Returns <see cref="FirewallPolicyState.Unknown"/> when the policy cannot be read;
        /// callers must treat that as "state undetermined" and never as
        /// <see cref="FirewallPolicyState.Allow"/>.
        /// </summary>
        /// <summary>
        /// Returns the default outbound action of the currently active profile, or null when the
        /// firewall policy could not be read. Never substitutes a value for an unreadable policy.
        /// </summary>
                        public static void CreateRule(INetFwRule2 rule)
        {
            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            INetFwRules? rulesCollection = null;
            try
            {
                if (firewallPolicy?.Rules == null)
                {
                    Debug.WriteLine("[ERROR] CreateRule: Firewall policy or rules collection is null.");
                    return;
                }
                rulesCollection = firewallPolicy.Rules;

                try
                {
                    Debug.WriteLine($"[FirewallRuleService] Committing Rule: {rule.Name}");
                    Debug.WriteLine($"[FirewallRuleService] - App: {rule.ApplicationName}");
                    Debug.WriteLine($"[FirewallRuleService] - Interfaces: {rule.InterfaceTypes}");
                    Debug.WriteLine($"[FirewallRuleService] - Protocol: {rule.Protocol}");
                }
                catch
                {
                    Debug.WriteLine("[FirewallRuleService] Could not read rule properties for logging.");
                }

                rulesCollection.Add(rule);
            }
            catch (COMException ex)
            {
                if (ex.HResult == HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS)
                {
                    Debug.WriteLine($"[WARN] CreateRule: Rule '{rule?.Name}' already exists. Skipping.");
                }
                else
                {
                    Debug.WriteLine($"[ERROR] CreateRule ('{rule?.Name ?? "null"}'): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                    throw;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] CreateRule ('{rule?.Name ?? "null"}'): Unexpected error. Type: {ex.GetType().Name}. Message: {ex.Message}");
                throw;
            }
            finally
            {
                if (rule != null)
                {
                    Marshal.ReleaseComObject(rule);
                }

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

        public static void UpdateRuleRemoteAddresses(string ruleName, string newRemoteAddresses)
        {
            if (string.IsNullOrEmpty(ruleName) || string.IsNullOrEmpty(newRemoteAddresses)) return;

            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null) return;

            INetFwRules? rulesCollection = null;
            try
            {
                rulesCollection = firewallPolicy.Rules;
                if (rulesCollection.Item(ruleName) is INetFwRule2 rule)
                {
                    rule.RemoteAddresses = newRemoteAddresses;
                    Marshal.ReleaseComObject(rule);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] UpdateRuleRemoteAddresses ('{ruleName}'): Failed. {ex.Message}");
            }
            finally
            {
                if (rulesCollection != null) Marshal.ReleaseComObject(rulesCollection);
                if (firewallPolicy != null) Marshal.ReleaseComObject(firewallPolicy);
            }
        }

                                        
            }
}
