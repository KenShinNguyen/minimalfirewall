using NetFwTypeLib;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall
{
    public class FirewallRuleService
    {
        private const int E_ACCESSDENIED = unchecked((int)0x80070005);
        private const int HRESULT_FROM_WIN32_ERROR_FILE_NOT_FOUND = unchecked((int)0x80070002);
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

        public static List<T> GetAllRulesMapped<T>(Func<INetFwRule2, T> mapper)
        {
            var mappedList = new List<T>();
            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null)
            {
                return mappedList;
            }

            var comRules = firewallPolicy.Rules;
            try
            {
                foreach (INetFwRule2 rule in comRules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    try
                    {
                        mappedList.Add(mapper(rule));
                    }
                    catch (Exception ex)
                    {
                        // Ignore rules that fail to map
                        Debug.WriteLine($"[WARN] GetAllRulesMapped: Failed to map firewall rule: {ex.Message}");
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(rule);
                    }
                }
            }
            finally
            {
                if (comRules != null)
                {
                    Marshal.ReleaseComObject(comRules);
                }

                if (firewallPolicy != null)
                {
                    Marshal.ReleaseComObject(firewallPolicy);
                }
            }
            return mappedList;
        }

        public static List<INetFwRule2> GetAllRules()
        {
            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null)
            {
                return [];
            }

            var rulesList = new List<INetFwRule2>();
            var comRules = firewallPolicy.Rules;
            try
            {
                foreach (INetFwRule2 rule in comRules)
                {
                    rulesList.Add(rule);
                }
                return rulesList;
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] GetAllRules: Failed to retrieve firewall rules. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                foreach (var rule in rulesList)
                {
                    Marshal.ReleaseComObject(rule);
                }
                return [];
            }
            finally
            {
                if (comRules != null)
                {
                    Marshal.ReleaseComObject(comRules);
                }

                if (firewallPolicy != null)
                {
                    Marshal.ReleaseComObject(firewallPolicy);
                }
            }
        }

        private static List<string> GetRuleNamesAndRelease(Func<INetFwRule2, bool> predicate)
        {
            var matchedNames = new List<string>();
            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null)
            {
                return matchedNames;
            }

            var comRules = firewallPolicy.Rules;
            try
            {
                foreach (INetFwRule2 rule in comRules)
                {
                    try
                    {
                        if (rule != null && predicate(rule))
                        {
                            matchedNames.Add(rule.Name);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[WARN] Error checking rule predicate: {ex.Message}");
                    }
                    finally
                    {
                        if (rule != null)
                        {
                            Marshal.ReleaseComObject(rule);
                        }
                    }
                }
            }
            finally
            {
                if (comRules != null)
                {
                    Marshal.ReleaseComObject(comRules);
                }

                if (firewallPolicy != null)
                {
                    Marshal.ReleaseComObject(firewallPolicy);
                }
            }
            return matchedNames;
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

        private static readonly NET_FW_PROFILE_TYPE2_[] AllProfiles =
        [
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
        ];

        private static string DescribeComError(COMException ex)
        {
            return ex.HResult == E_ACCESSDENIED
                ? "Access denied - administrator privileges are required."
                : $"HResult 0x{ex.HResult:X8}: {ex.Message}";
        }

        /// <summary>
        /// Applies <paramref name="action"/> to every firewall profile as one unit: each write is
        /// read back to confirm it took effect, and if any profile fails the profiles that already
        /// changed are restored to their previous action. A partial application is reported as a
        /// failure, so a caller can never tell the user they are protected when only some profiles
        /// were actually updated.
        /// </summary>
        public static SetDefaultOutboundActionResult SetDefaultOutboundAction(NET_FW_ACTION_ action)
        {
            INetFwPolicy2? firewallPolicy;
            try
            {
                firewallPolicy = GetLocalPolicy();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] SetDefaultOutboundAction: Could not open firewall policy. {ex.Message}");
                return new SetDefaultOutboundActionResult { RequestedAction = action, PolicyUnavailable = true };
            }

            if (firewallPolicy == null)
            {
                return new SetDefaultOutboundActionResult { RequestedAction = action, PolicyUnavailable = true };
            }

            var results = new List<ProfileActionResult>();
            var changed = new List<(NET_FW_PROFILE_TYPE2_ Profile, NET_FW_ACTION_ Previous)>();

            try
            {
                foreach (NET_FW_PROFILE_TYPE2_ profile in AllProfiles)
                {
                    NET_FW_ACTION_ previous;
                    try
                    {
                        previous = firewallPolicy.DefaultOutboundAction[profile];
                    }
                    catch (COMException ex)
                    {
                        Debug.WriteLine($"[ERROR] SetDefaultOutboundAction ({profile}): Could not read current action. HResult: 0x{ex.HResult:X8}.");
                        results.Add(new ProfileActionResult
                        {
                            Profile = profile,
                            Succeeded = false,
                            Error = DescribeComError(ex)
                        });
                        continue;
                    }

                    if (previous == action)
                    {
                        // Already correct: nothing was applied, so there is nothing to roll back here.
                        results.Add(new ProfileActionResult
                        {
                            Profile = profile,
                            Succeeded = true,
                            PreviousAction = previous
                        });
                        continue;
                    }

                    try
                    {
                        firewallPolicy.set_DefaultOutboundAction(profile, action);
                    }
                    catch (COMException ex)
                    {
                        Debug.WriteLine($"[ERROR] SetDefaultOutboundAction ({profile}): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                        results.Add(new ProfileActionResult
                        {
                            Profile = profile,
                            Succeeded = false,
                            PreviousAction = previous,
                            Error = DescribeComError(ex)
                        });
                        continue;
                    }

                    // Read the value back. A write that silently does not stick (Group Policy
                    // override, for example) is indistinguishable from success without this.
                    NET_FW_ACTION_ verified;
                    try
                    {
                        verified = firewallPolicy.DefaultOutboundAction[profile];
                    }
                    catch (COMException ex)
                    {
                        changed.Add((profile, previous));
                        results.Add(new ProfileActionResult
                        {
                            Profile = profile,
                            Succeeded = false,
                            PreviousAction = previous,
                            Error = $"Could not verify the change: {DescribeComError(ex)}"
                        });
                        continue;
                    }

                    if (verified != action)
                    {
                        results.Add(new ProfileActionResult
                        {
                            Profile = profile,
                            Succeeded = false,
                            PreviousAction = previous,
                            Error = "The policy did not retain the requested action (it may be overridden by Group Policy)."
                        });
                        continue;
                    }

                    changed.Add((profile, previous));
                    results.Add(new ProfileActionResult
                    {
                        Profile = profile,
                        Succeeded = true,
                        PreviousAction = previous
                    });
                }

                bool anyFailed = results.Exists(r => !r.Succeeded);
                bool rolledBack = false;
                bool rollbackIncomplete = false;

                if (anyFailed && changed.Count > 0)
                {
                    rolledBack = true;
                    foreach (var (profile, previous) in changed)
                    {
                        try
                        {
                            firewallPolicy.set_DefaultOutboundAction(profile, previous);
                        }
                        catch (COMException ex)
                        {
                            rollbackIncomplete = true;
                            Debug.WriteLine($"[ERROR] SetDefaultOutboundAction rollback ({profile}): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                        }
                    }
                }

                return new SetDefaultOutboundActionResult
                {
                    RequestedAction = action,
                    Profiles = results,
                    RolledBack = rolledBack,
                    RollbackIncomplete = rollbackIncomplete
                };
            }
            finally
            {
                Marshal.ReleaseComObject(firewallPolicy);
            }
        }

        public static List<string> GetRuleNamesByPathAndDirection(string appPath, NET_FW_RULE_DIRECTION_ direction)
        {
            var rules = GetRulesByPathAndDirection(appPath, direction);
            var names = rules.Select(r => r.Name).ToList();
            foreach (var rule in rules)
            {
                Marshal.ReleaseComObject(rule);
            }
            return names;
        }

        public static List<INetFwRule2> GetRulesByPathAndDirection(string appPath, NET_FW_RULE_DIRECTION_ direction)
        {
            if (string.IsNullOrEmpty(appPath))
            {
                return [];
            }

            string normalizedAppPath = PathResolver.NormalizePath(appPath);
            var matchingRules = new List<INetFwRule2>();

            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null)
            {
                return matchingRules;
            }

            var comRules = firewallPolicy.Rules;
            try
            {
                foreach (INetFwRule2 rule in comRules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    bool keep = false;
                    try
                    {
                        if (!string.IsNullOrEmpty(rule.ApplicationName) &&
                            string.Equals(PathResolver.NormalizePath(rule.ApplicationName), normalizedAppPath, StringComparison.OrdinalIgnoreCase) &&
                            rule.Direction == direction)
                        {
                            matchingRules.Add(rule);
                            keep = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[WARN] GetRulesByPathAndDirection: Failed to inspect firewall rule: {ex.Message}");
                    }
                    finally
                    {
                        if (!keep)
                        {
                            Marshal.ReleaseComObject(rule);
                        }
                    }
                }
            }
            finally
            {
                if (comRules != null)
                {
                    Marshal.ReleaseComObject(comRules);
                }

                if (firewallPolicy != null)
                {
                    Marshal.ReleaseComObject(firewallPolicy);
                }
            }
            return matchingRules;
        }

        /// <summary>
        /// Reads the default outbound action of the active profile as a tri-state.
        /// Returns <see cref="FirewallPolicyState.Unknown"/> when the policy cannot be read;
        /// callers must treat that as "state undetermined" and never as
        /// <see cref="FirewallPolicyState.Allow"/>.
        /// </summary>
        public static FirewallPolicyState GetDefaultOutboundState()
        {
            NET_FW_ACTION_? action = TryGetDefaultOutboundAction();
            if (action == null)
            {
                return FirewallPolicyState.Unknown;
            }

            return action.Value == NET_FW_ACTION_.NET_FW_ACTION_BLOCK
                ? FirewallPolicyState.Block
                : FirewallPolicyState.Allow;
        }

        /// <summary>
        /// Returns the default outbound action of the currently active profile, or null when the
        /// firewall policy could not be read. Never substitutes a value for an unreadable policy.
        /// </summary>
        public static NET_FW_ACTION_? TryGetDefaultOutboundAction()
        {
            INetFwPolicy2? firewallPolicy;
            try
            {
                firewallPolicy = GetLocalPolicy();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] TryGetDefaultOutboundAction: Could not open firewall policy. {ex.Message}");
                return null;
            }

            if (firewallPolicy == null)
            {
                return null;
            }

            try
            {
                var currentProfileTypes = (NET_FW_PROFILE_TYPE2_)firewallPolicy.CurrentProfileTypes;
                if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) != 0)
                {
                    return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC];
                }
                if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) != 0)
                {
                    return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE];
                }
                if ((currentProfileTypes & NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) != 0)
                {
                    return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN];
                }

                Debug.WriteLine("[WARN] TryGetDefaultOutboundAction: No specific profile type identified as active. Falling back to Public.");
                return firewallPolicy.DefaultOutboundAction[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC];
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] TryGetDefaultOutboundAction: Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                return null;
            }
            finally
            {
                Marshal.ReleaseComObject(firewallPolicy);
            }
        }

        private static List<string> ExecuteDeleteAndReturnNames(Func<INetFwRule2, bool> predicate)
        {
            var rulesToRemove = GetRuleNamesAndRelease(predicate);
            DeleteRulesByName(rulesToRemove);
            return rulesToRemove;
        }

        public static List<string> DeleteRulesByPath(List<string> appPaths)
        {
            if (appPaths.Count == 0)
            {
                return [];
            }

            var pathSet = new HashSet<string>(appPaths.Select(PathResolver.NormalizePath), StringComparer.OrdinalIgnoreCase);

            return ExecuteDeleteAndReturnNames(rule =>
                !string.IsNullOrEmpty(rule.ApplicationName) &&
                pathSet.Contains(PathResolver.NormalizePath(rule.ApplicationName))
            );
        }

        public static List<string> DeleteRulesByServiceName(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName))
            {
                return [];
            }

            return ExecuteDeleteAndReturnNames(rule => string.Equals(rule.serviceName, serviceName, StringComparison.OrdinalIgnoreCase));
        }

        public static List<string> DeleteConflictingServiceRules(string serviceName, NET_FW_ACTION_ newAction, NET_FW_RULE_DIRECTION_ newDirection)
        {
            if (string.IsNullOrEmpty(serviceName))
            {
                return [];
            }

            NET_FW_ACTION_ conflictingAction = (newAction == NET_FW_ACTION_.NET_FW_ACTION_ALLOW)
                ? NET_FW_ACTION_.NET_FW_ACTION_BLOCK
                : NET_FW_ACTION_.NET_FW_ACTION_ALLOW;

            return ExecuteDeleteAndReturnNames(rule =>
                string.Equals(rule.serviceName, serviceName, StringComparison.OrdinalIgnoreCase) &&
                (rule.Direction == newDirection || rule.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_MAX) &&
                rule.Action == conflictingAction
            );
        }

        public static List<string> DeleteUwpRules(List<string> packageFamilyNames)
        {
            if (packageFamilyNames.Count == 0)
            {
                return [];
            }

            var pfnSet = new HashSet<string>(packageFamilyNames, StringComparer.OrdinalIgnoreCase);

            return ExecuteDeleteAndReturnNames(rule =>
            {
                if (rule.Description?.StartsWith(MFWConstants.UwpDescriptionPrefix, StringComparison.Ordinal) == true)
                {
                    string pfnInRule = rule.Description[MFWConstants.UwpDescriptionPrefix.Length..];
                    return pfnSet.Contains(pfnInRule);
                }
                return false;
            });
        }

        public static void DeleteRulesByName(List<string> ruleNames)
        {
            if (ruleNames.Count == 0)
            {
                return;
            }

            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy?.Rules == null)
            {
                return;
            }

            var rulesCollection = firewallPolicy.Rules;
            try
            {
                foreach (var name in ruleNames)
                {
                    try
                    {
                        rulesCollection.Remove(name);
                    }
                    catch (FileNotFoundException)
                    {
                        Debug.WriteLine($"[WARN] DeleteRulesByName: Rule '{name}' not found for removal.");
                    }
                    catch (COMException ex)
                    {
                        Debug.WriteLine($"[ERROR] DeleteRulesByName ('{name}'): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
                        if (ex.HResult == E_ACCESSDENIED)
                        {
                            Debug.WriteLine($"[ERROR] DeleteRulesByName ('{name}'): Access Denied.");
                        }
                        else if (ex.HResult == HRESULT_FROM_WIN32_ERROR_FILE_NOT_FOUND)
                        {
                            Debug.WriteLine($"[WARN] DeleteRulesByName: Rule '{name}' not found (reported via COMException HResult).");
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[ERROR] DeleteRulesByName ('{name}'): Unexpected error during removal. Type: {ex.GetType().Name}. Message: {ex.Message}");
                    }
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

        public static List<string> DeleteRulesByDescription(string description)
        {
            if (string.IsNullOrEmpty(description))
            {
                return [];
            }

            return ExecuteDeleteAndReturnNames(rule => string.Equals(rule.Description, description, StringComparison.OrdinalIgnoreCase));
        }

        public static List<string> DeleteRulesByGroup(string groupName)
        {
            if (string.IsNullOrEmpty(groupName))
            {
                return [];
            }

            return ExecuteDeleteAndReturnNames(rule => string.Equals(rule.Grouping, groupName, StringComparison.OrdinalIgnoreCase));
        }

        public static void DeleteAllMfwRules()
        {
            var rulesToRemove = GetRuleNamesAndRelease(rule =>
                !string.IsNullOrEmpty(rule.Grouping) &&
                (rule.Grouping.EndsWith(MFWConstants.MfwRuleSuffix) ||
                 rule.Grouping == MFWConstants.MainRuleGroup ||
                 rule.Grouping == MFWConstants.WildcardRuleGroup)
            );

            Debug.WriteLine($"[INFO] DeleteAllMfwRules: Identified {rulesToRemove.Count} MFW rules for deletion.");

            if (rulesToRemove.Count > 0)
            {
                DeleteRulesByName(rulesToRemove);
                Debug.WriteLine($"[INFO] DeleteAllMfwRules: Requested deletion of {rulesToRemove.Count} MFW rules.");
            }
        }

        private static void SetRuleEnabledState(string ruleName, bool isEnabled, string callerName)
        {
            if (string.IsNullOrEmpty(ruleName))
            {
                return;
            }

            INetFwPolicy2 firewallPolicy = GetLocalPolicy();
            if (firewallPolicy == null)
            {
                return;
            }

            INetFwRules? rulesCollection = null;
            try
            {
                rulesCollection = firewallPolicy.Rules;
                if (rulesCollection == null)
                {
                    return;
                }

                if (rulesCollection.Item(ruleName) is INetFwRule2 rule)
                {
                    rule.Enabled = isEnabled;
                    Marshal.ReleaseComObject(rule);
                }
            }
            catch (FileNotFoundException)
            {
                Debug.WriteLine($"[WARN] {callerName}: Rule '{ruleName}' not found.");
            }
            catch (COMException ex)
            {
                Debug.WriteLine($"[ERROR] {callerName} ('{ruleName}'): Failed. HResult: 0x{ex.HResult:X8}. Message: {ex.Message}");
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

        public void DisableRuleByName(string ruleName) => SetRuleEnabledState(ruleName, false, nameof(DisableRuleByName));

        public void EnableRuleByName(string ruleName) => SetRuleEnabledState(ruleName, true, nameof(EnableRuleByName));
    }
}
