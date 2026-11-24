using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinimalFirewall;

public sealed class WindowsFirewallRuleLifecycleBackend : IFirewallRuleLifecycleBackend
{
    private const int E_ACCESSDENIED = unchecked((int)0x80070005);
    private const int HRESULT_FROM_WIN32_ERROR_FILE_NOT_FOUND = unchecked((int)0x80070002);
    private static readonly Lazy<Type?> _firewallPolicyType = new(() => Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

private static INetFwPolicy2 GetLocalPolicy()
        {
            if (_firewallPolicyType.Value == null)
            {
                throw new InvalidOperationException("Firewall policy type could not be retrieved.");
            }
            return (INetFwPolicy2)Activator.CreateInstance(_firewallPolicyType.Value)!;
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

private static void DeleteAllMfwRulesCore()
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

    public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths)
        => Execute(() => DeleteRulesByPath([.. appPaths]), "delete rules by path");

    public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames)
        => Execute(() => DeleteUwpRules([.. packageFamilyNames]), "delete UWP rules");

    public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames)
        => Execute(() => DeleteRulesByName([.. ruleNames]), "delete rules by name");

    public FirewallRuleLifecycleOperationResult DeleteByDescription(string description)
        => Execute(() => DeleteRulesByDescription(description), "delete rules by description");

    public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName)
        => Execute(() => DeleteRulesByGroup(groupName), "delete rules by group");

    public FirewallRuleLifecycleOperationResult DeleteAllMfwRules()
        => Execute(DeleteAllMfwRulesCore, "delete all Minimal Firewall rules");

    public FirewallRuleLifecycleOperationResult EnableByName(string ruleName)
        => Execute(() => SetRuleEnabledState(ruleName, true, nameof(EnableByName)), "enable rule");

    public FirewallRuleLifecycleOperationResult DisableByName(string ruleName)
        => Execute(() => SetRuleEnabledState(ruleName, false, nameof(DisableByName)), "disable rule");

    private static FirewallRuleLifecycleOperationResult Execute(
        Action operation,
        string operationName)
    {
        try
        {
            operation();
            return FirewallRuleLifecycleOperationResult.Success();
        }
        catch (COMException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed with HRESULT 0x{ex.HResult:X8}: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            return FirewallRuleLifecycleOperationResult.Failure(
                $"{operationName} failed: {ex.Message}", ex);
        }
    }
}
