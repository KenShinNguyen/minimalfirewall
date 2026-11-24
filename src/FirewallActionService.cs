using System.Data;
using System.IO;
using MinimalFirewall.TypedObjects;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Diagnostics;
using System;
using System.Threading;
using System.Text.Json;

namespace MinimalFirewall
{
    public partial class FirewallActionsService(
        UserActivityLogger activityLogger,
        FirewallEventListenerService eventListenerService,
        FirewallSentryService sentryService,
        PublisherWhitelistService whitelistService,
        WildcardRuleService wildcardRuleService,
        FirewallDataService dataService,
        IFirewallBackend? policyBackend = null,
        ISystemFirewallRuleBackend? systemRuleBackend = null,
        IFirewallRuleLifecycleBackend? ruleLifecycleBackend = null,
        IFirewallRuleQueryBackend? ruleQueryBackend = null,
        IFirewallRuleCreationBackend? ruleCreationBackend = null) : IDisposable
    {
        public FirewallSentryService SentryService => sentryService;

        private readonly PublisherWhitelistService _whitelistService = whitelistService;
        private readonly TemporaryRuleManager _temporaryRuleManager = new();
        private readonly WildcardRuleService _wildcardRuleService = wildcardRuleService;
        private readonly FirewallDataService _dataService = dataService;
        private readonly IFirewallBackend _policyBackend = policyBackend ?? new WindowsFirewallBackend();
        private readonly ISystemFirewallRuleBackend _systemRuleBackend = systemRuleBackend ?? new WindowsSystemFirewallRuleBackend();
        private readonly IFirewallRuleLifecycleBackend _ruleLifecycleBackend = ruleLifecycleBackend ?? new WindowsFirewallRuleLifecycleBackend();
        private readonly IFirewallRuleQueryBackend _ruleQueryBackend = ruleQueryBackend ?? new WindowsFirewallRuleQueryBackend();
        private readonly IFirewallRuleCreationBackend _ruleCreationBackend = ruleCreationBackend ?? new WindowsFirewallRuleCreationBackend();

        // Timer cleanup management
        private readonly ConcurrentDictionary<string, System.Threading.Timer> _temporaryRuleTimers = new();
        private bool _disposed;

        private const string CryptoRuleName = "Minimal Firewall System - Certificate Checks";
        private const string DhcpRuleName = "Minimal Firewall System - DHCP Client";

        public BackgroundFirewallTaskService? BackgroundTaskService { get; set; }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    foreach (var timer in _temporaryRuleTimers.Values)
                    {
                        timer.Dispose();
                    }
                    _temporaryRuleTimers.Clear();
                }
                _disposed = true;
            }
        }

        private void LogLifecycleFailure(FirewallRuleLifecycleOperationResult result, string message)
        {
            if (result.Exception is not null)
            {
                // Preserve exception type and HRESULT in the error log instead of downgrading to debug output.
                activityLogger.LogException(message.TrimEnd('.'), result.Exception);
                return;
            }

            activityLogger.LogDebug(
                string.IsNullOrWhiteSpace(result.Error) ? message : $"{message} {result.Error}");
        }

        public void CleanupTemporaryRulesOnStartup()
        {
            var expiredRules = _temporaryRuleManager.GetExpiredRules();
            if (expiredRules.Count != 0)
            {
                var ruleNamesToRemove = expiredRules.Keys.ToList();
                var result = _ruleLifecycleBackend.DeleteByName(ruleNamesToRemove);
                if (!result.Succeeded)
                {
                    LogLifecycleFailure(result, "CleanupTemporaryRulesOnStartup failed.");
                    return;
                }

                foreach (var ruleName in ruleNamesToRemove)
                {
                    _temporaryRuleManager.Remove(ruleName);
                }

                activityLogger.LogDebug($"Cleaned up {ruleNamesToRemove.Count} expired temporary rules on startup.");
            }
        }

        private void LogQueryFailure<T>(FirewallRuleQueryResult<T> result, string message)
        {
            if (result.Exception is not null)
            {
                activityLogger.LogException(message.TrimEnd('.'), result.Exception);
                return;
            }

            activityLogger.LogDebug(
                string.IsNullOrWhiteSpace(result.Error) ? message : $"{message} {result.Error}");
        }

        private void LogRuleFailures<T>(FirewallRuleQueryResult<T> result, string context)
        {
            foreach (var failure in result.RuleFailures)
            {
                activityLogger.LogException($"{context} '{failure.RuleName}'", failure.Exception);
            }
        }

        private void FindAndQueueDeleteForGeneralBlockRule(string appPath)
        {
            string normalizedAppPath = PathResolver.NormalizePath(appPath);
            var query = _ruleQueryBackend.GetMfwRules();
            if (!query.Succeeded || query.Value is null)
            {
                LogQueryFailure(query, $"FindAndQueueDeleteForGeneralBlockRule failed for {appPath}.");
                return;
            }

            LogRuleFailures(query, "FindAndQueueDeleteForGeneralBlockRule read rule");

            var rulesToDelete = new List<string>();
            foreach (var rule in query.Value)
            {
                if (rule.Protocol != 256 || !rule.IsBlock)
                {
                    continue;
                }

                if (rule.LocalPorts != "*" || rule.RemotePorts != "*")
                {
                    continue;
                }

                if (string.Equals(PathResolver.NormalizePath(rule.ApplicationName), normalizedAppPath, StringComparison.OrdinalIgnoreCase))
                {
                    rulesToDelete.Add(rule.Name);
                }
            }

            if (rulesToDelete.Count != 0)
            {
                activityLogger.LogDebug($"Auto-deleting general block rule(s) for {appPath} to apply new Allow rule: {string.Join(", ", rulesToDelete)}");
                var result = _ruleLifecycleBackend.DeleteByName(rulesToDelete);
                if (!result.Succeeded)
                {
                    LogLifecycleFailure(result, $"Auto-deleting rules for {appPath} failed.");
                    return;
                }

                foreach (var name in rulesToDelete)
                {
                    activityLogger.LogChange("Rule Auto-Deleted", name);
                }
            }
        }

        public void ApplyApplicationRuleChange(List<string> appPaths, string action, string? wildcardSourcePath = null, string? autoAllowedPublisher = null)
        {
            if (appPaths == null) return;

            var normalizedAppPaths = appPaths.Select(PathResolver.NormalizePath).Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (action.StartsWith("Allow", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var appPath in normalizedAppPaths)
                {
                    FindAndQueueDeleteForGeneralBlockRule(appPath);
                }
            }

            foreach (var appPath in normalizedAppPaths)
            {
                if (!File.Exists(appPath) && !appPath.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase) && !appPath.Contains("SystemApps", StringComparison.OrdinalIgnoreCase))
                {
                    activityLogger.LogDebug($"[Validation] Skipped creating rule for non-existent path: {appPath}");
                    continue;
                }

                var rulesToRemove = new List<string>();
                if (string.IsNullOrEmpty(wildcardSourcePath))
                {
                    if (action.Contains("Inbound") || action.Contains("(All)"))
                    {
                        var inboundQuery = _ruleQueryBackend.GetRuleNamesByPathAndDirection(appPath, Directions.Incoming);
                        if (inboundQuery.Succeeded && inboundQuery.Value is not null)
                        {
                            rulesToRemove.AddRange(inboundQuery.Value);
                            LogRuleFailures(inboundQuery, "Get conflicting inbound application rules");
                        }
                        else
                        {
                            LogQueryFailure(inboundQuery, $"Get conflicting inbound application rules for {appPath} failed.");
                        }
                    }
                    if (action.Contains("Outbound") || action.Contains("(All)"))
                    {
                        var outboundQuery = _ruleQueryBackend.GetRuleNamesByPathAndDirection(appPath, Directions.Outgoing);
                        if (outboundQuery.Succeeded && outboundQuery.Value is not null)
                        {
                            rulesToRemove.AddRange(outboundQuery.Value);
                            LogRuleFailures(outboundQuery, "Get conflicting outbound application rules");
                        }
                        else
                        {
                            LogQueryFailure(outboundQuery, $"Get conflicting outbound application rules for {appPath} failed.");
                        }
                    }
                }

                if (rulesToRemove.Count != 0)
                {
                    var deleteResult = _ruleLifecycleBackend.DeleteByName(rulesToRemove);
                    if (!deleteResult.Succeeded)
                    {
                        LogLifecycleFailure(deleteResult, $"Delete conflicting application rules for {appPath} failed.");
                        continue;
                    }
                }

                string appName = Path.GetFileNameWithoutExtension(appPath);
                void createRule(string baseName, Directions dir, Actions act)
                {
                    string description;
                    if (!string.IsNullOrEmpty(wildcardSourcePath))
                    {
                        description = $"{MFWConstants.WildcardDescriptionPrefix}{wildcardSourcePath}]";
                    }
                    else if (!string.IsNullOrEmpty(autoAllowedPublisher))
                    {
                        description = $"{MFWConstants.AutoAllowPublisherPrefix}{autoAllowedPublisher}]";
                    }
                    else
                    {
                        description = "";
                    }
                    CreateApplicationRule(baseName, appPath, dir, act, ProtocolTypes.Any.Value, description);
                }

                ApplyRuleAction(appName, action, createRule);

                activityLogger.LogChange("Rule Changed", action + " for " + appPath);
            }
        }

        private static void ProcessTcpAndUdpRules(Directions parsedDirection, Action<Directions, int, string> ruleCreationAction)
        {
            (int Code, string Suffix)[] protocols = [(6, " - TCP"), (17, " - UDP")];
            foreach (var (Code, Suffix) in protocols)
            {
                if (parsedDirection.HasFlag(Directions.Incoming))
                {
                    ruleCreationAction(Directions.Incoming, Code, Suffix);
                }
                if (parsedDirection.HasFlag(Directions.Outgoing))
                {
                    ruleCreationAction(Directions.Outgoing, Code, Suffix);
                }
            }
        }

        public void ApplyServiceRuleChange(string serviceName, string action, string? appPath = null)
        {
            if (string.IsNullOrEmpty(serviceName))
            {
                return;
            }

            if (!ParseActionString(action, out Actions parsedAction, out Directions parsedDirection))
            {
                return;
            }

            // DeleteConflictingServiceRules deletes the matched rules itself.
            if (parsedDirection.HasFlag(Directions.Incoming))
            {
                _ruleLifecycleBackend.DeleteConflictingServiceRules(serviceName, parsedAction, Directions.Incoming);
            }
            if (parsedDirection.HasFlag(Directions.Outgoing))
            {
                _ruleLifecycleBackend.DeleteConflictingServiceRules(serviceName, parsedAction, Directions.Outgoing);
            }

            ProcessTcpAndUdpRules(parsedDirection, (dir, proto, suffix) =>
            {
                string dirStr = dir == Directions.Incoming ? "In" : "Out";
                CreateServiceRule($"{serviceName} - {dirStr}{suffix}", serviceName, dir, parsedAction, proto, appPath);
            });

            activityLogger.LogChange("Service Rule Changed", action + " for " + serviceName);
        }

        public void ApplyUwpRuleChange(List<UwpApp> uwpApps, string action)
        {
            var validApps = new List<UwpApp>();
            var cachedUwpApps = _dataService.LoadUwpAppsFromCache();
            var cachedPfnSet = new HashSet<string>(cachedUwpApps.Select(a => a.PackageFamilyName), StringComparer.OrdinalIgnoreCase);

            foreach (var app in uwpApps)
            {
                if (cachedPfnSet.Contains(app.PackageFamilyName))
                {
                    validApps.Add(app);
                }
                else
                {
                    activityLogger.LogDebug($"[Validation] Skipped creating rule for non-existent UWP app: {app.Name} ({app.PackageFamilyName})");
                }
            }

            if (validApps.Count == 0)
            {
                return;
            }

            var packageFamilyNames = validApps.Select(app => app.PackageFamilyName).ToList();
            // DeleteUwpRules already removes the old rules; new rules reuse the same
            // names, so deleting the returned names afterwards would destroy them.
            var deleteResult = _ruleLifecycleBackend.DeleteUwp(packageFamilyNames);
            if (!deleteResult.Succeeded)
            {
                LogLifecycleFailure(deleteResult, "Delete conflicting UWP rules failed.");
                return;
            }
            foreach (var app in validApps)
            {
                void createRule(string name, Directions dir, Actions act) => CreateUwpRule(name, app.PackageFamilyName, dir, act, ProtocolTypes.Any.Value);
                ApplyRuleAction(app.Name, action, createRule);
                activityLogger.LogChange("UWP Rule Changed", action + " for " + app.Name);
            }
        }

        private void ExecuteRuleDeletion(
            IReadOnlyList<string> items,
            Func<IReadOnlyList<string>, FirewallRuleLifecycleOperationResult> deleteAction,
            string logPrefix)
        {
            if (items.Count == 0)
            {
                return;
            }

            var result = deleteAction(items);
            if (!result.Succeeded)
            {
                LogLifecycleFailure(result, $"Delete{logPrefix.Replace(" ", "")}s failed for {string.Join(",", items)}.");
                return;
            }

            foreach (var item in items)
            {
                activityLogger.LogChange($"{logPrefix} Deleted", item);
            }
        }

        public void DeleteApplicationRules(List<string> appPaths) =>
            ExecuteRuleDeletion(appPaths, _ruleLifecycleBackend.DeleteByPath, "Rule");

        public void DeleteUwpRules(List<string> packageFamilyNames) =>
            ExecuteRuleDeletion(packageFamilyNames, _ruleLifecycleBackend.DeleteUwp, "UWP Rule");

        public void DeleteAdvancedRules(List<string> ruleNames) =>
            ExecuteRuleDeletion(ruleNames, _ruleLifecycleBackend.DeleteByName, "Advanced Rule");

        public void DeleteRulesForWildcard(WildcardRule wildcard)
        {
            if (wildcard == null)
            {
                return;
            }

            string descriptionTag = $"{MFWConstants.WildcardDescriptionPrefix}{wildcard.FolderPath}]";
            var result = _ruleLifecycleBackend.DeleteByDescription(descriptionTag);
            if (!result.Succeeded)
            {
                LogLifecycleFailure(result, $"DeleteRulesForWildcard failed for {wildcard.FolderPath}.");
                return;
            }

            activityLogger.LogChange("Wildcard Rules Deleted", $"Deleted rules for folder {wildcard.FolderPath}");
        }



        // Consolidated helper for System Rules (Crypto/DHCP)
        protected bool ManageSystemRule(
            string ruleName,
            string description,
            string applicationName,
            string serviceName,
            SystemFirewallRuleProtocol protocol,
            string remotePorts,
            string localPorts,
            bool enable)
        {
            var definition = new SystemFirewallRuleDefinition(
                ruleName,
                description,
                applicationName,
                serviceName,
                SystemFirewallRuleDirection.Outbound,
                SystemFirewallRuleAction.Allow,
                protocol,
                remotePorts,
                localPorts,
                Enabled: true);

            var result = enable
                ? _systemRuleBackend.EnsureRule(definition)
                : _systemRuleBackend.RemoveRule(ruleName);

            if (!result.Succeeded)
            {
                activityLogger.LogException(
                    $"ManageSystemRule '{ruleName}' (enable: {enable})",
                    new InvalidOperationException(result.Error ?? "System firewall rule operation failed."));
                return false;
            }

            activityLogger.LogDebug(
                enable
                    ? $"Ensured system rule: {ruleName}"
                    : $"Disabled/Deleted system rule: {ruleName}");
            return true;
        }

        private bool ManageCryptoServiceRule(bool enable)
        {
            return ManageSystemRule(
                CryptoRuleName,
                "Allows Windows to check for certificate revocation online. Essential for the 'auto-allow trusted' feature in Lockdown Mode.",
                "svchost.exe",
                "CryptSvc",
                SystemFirewallRuleProtocol.Tcp,
                "80,443", // Remote
                "*",      // Local
                enable);
        }

        private bool ManageDhcpClientRule(bool enable)
        {
            return ManageSystemRule(
                DhcpRuleName,
                "Allows the DHCP Client (Dhcp) service to get an IP address from your router. Essential for network connectivity in Lockdown Mode.",
                "svchost.exe",
                "Dhcp",
                SystemFirewallRuleProtocol.Udp,
                "67",  // Remote
                "68",  // Local
                enable);
        }

        // Thread-safe wrapper for MessageBox
        private static void SafeShowMessageBox(string text, string caption, MessageBoxButtons buttons, MessageBoxIcon icon)
        {
            if (Application.OpenForms.Count > 0 &&
                Application.OpenForms[0] is { } form)
            {
                if (form.InvokeRequired)
                {
                    form.Invoke(new Action(() => MessageBox.Show(form, text, caption, buttons, icon)));
                    return;
                }
            }
            MessageBox.Show(text, caption, buttons, icon);
        }

        protected virtual void ShowLockdownMessage(string text, string caption)
        {
            SafeShowMessageBox(text, caption, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        protected virtual void ShowBatchCreationErrors(string text)
        {
            SafeShowMessageBox(text, "Batch Creation Errors", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        public void ToggleLockdown()
        {
            if (!FirewallPolicyGuard.TryGetToggleAction(
                    _policyBackend,
                    out var targetAction))
            {
                activityLogger.LogDebug("Toggle Lockdown aborted: the current firewall policy could not be read.");
                ShowLockdownMessage(
                    "The current Windows Firewall policy could not be read, so Lockdown was not changed.\\n\\n" +
                    "Check that the Windows Firewall service is running and that Minimal Firewall is running as Administrator.",
                    "Firewall State Unknown");
                return;
            }

            bool newLockdownState = targetAction == FirewallOutboundAction.Block;
            var currentState = newLockdownState
                ? FirewallPolicyState.Allow
                : FirewallPolicyState.Block;

            activityLogger.LogDebug($"Toggling Lockdown. Current state: {(currentState == FirewallPolicyState.Block ? "Locked" : "Unlocked")}. New state: {(newLockdownState ? "Locked" : "Unlocked")}.");

            try
            {
                PrepareLockdownPrerequisites(newLockdownState);
            }
            catch (InvalidOperationException ex)
            {
                activityLogger.LogException("PrepareLockdownPrerequisites", ex);
                ShowLockdownMessage(
                    "The system firewall rules could not be prepared, so Lockdown was not changed.\\n\\n" +
                    (string.IsNullOrWhiteSpace(ex.Message) ? "Check the Windows Firewall service and run Minimal Firewall as Administrator." : ex.Message),
                    "Lockdown Error");
                return;
            }

            if (newLockdownState && !VerifyLockdownAuditPolicy())
            {
                ShowLockdownMessage(
                    "Failed to verify that Windows Security Auditing was enabled.\\n\\n" +
                    "The Lockdown dashboard will not be able to detect blocked connections.\\n\\n" +
                    "Potential Causes:\\n" +
                    "1. A local or domain Group Policy is preventing this change.\\n" +
                    "2. Other security software is blocking this action.\\n\\n" +
                    "The firewall's default policy will be set back to 'Allow' for safety.",
                    "Lockdown Mode Failed");

                var rollbackSucceeded = FirewallPolicyGuard.TrySetDefaultOutboundAction(
                    _policyBackend,
                    FirewallOutboundAction.Allow,
                    out var rollbackResult);

                if (!rollbackSucceeded)
                {
                    var rollbackSummary = rollbackResult?.DiagnosticSummary;
                    activityLogger.LogDebug(
                        string.IsNullOrWhiteSpace(rollbackSummary)
                            ? "Failed to revert outbound policy to Allow after audit failure."
                            : $"Failed to revert outbound policy to Allow after audit failure.\\n{rollbackSummary}");

                    ShowLockdownMessage(
                        string.IsNullOrWhiteSpace(rollbackSummary)
                            ? "The firewall policy could not be set back to 'Allow'."
                            : "The firewall policy could not be set back to 'Allow'.\\n\\n" + rollbackSummary,
                        "Firewall Policy Error");
                }

                activityLogger.LogDebug("Lockdown Mode Failed: Could not enable audit policy.");
                return;
            }

            var applySucceeded = FirewallPolicyGuard.TrySetDefaultOutboundAction(
                _policyBackend,
                targetAction,
                out var applyResult);

            if (!applySucceeded)
            {
                var applySummary = applyResult?.DiagnosticSummary;
                activityLogger.LogDebug(
                    string.IsNullOrWhiteSpace(applySummary)
                        ? "Failed to change default outbound policy."
                        : $"Failed to change default outbound policy.\\n{applySummary}");

                string message = applyResult?.RollbackIncomplete == true
                    ? "The default outbound policy could not be changed, and restoring the previous policy did not fully succeed.\\n\\n"
                    : "The default outbound policy was not changed.\\n\\n";

                ShowLockdownMessage(
                    message + (string.IsNullOrWhiteSpace(applySummary)
                        ? "Failed to change the default outbound policy."
                        : applySummary),
                    "Lockdown Error");
                return;
            }

            CompleteLockdownTransition(newLockdownState);
        }

        protected virtual void PrepareLockdownPrerequisites(bool enableLockdown)
        {
            try
            {
                AdminTaskService.SetAuditPolicy(enableLockdown);
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                activityLogger.LogException("SetAuditPolicy", ex);
            }

            if (!ManageCryptoServiceRule(enableLockdown) ||
                !ManageDhcpClientRule(enableLockdown) ||
                !ManageWslRules(enableLockdown))
            {
                throw new InvalidOperationException(
                    "One or more system firewall rules could not be prepared for the requested Lockdown state.");
            }
        }

        protected virtual bool VerifyLockdownAuditPolicy()
            => AdminTaskService.IsWfpConnectionAuditPolicyEnabled();

        protected virtual void CompleteLockdownTransition(bool lockdownEnabled)
        {
            if (lockdownEnabled)
            {
                eventListenerService.Start();
            }
            else
            {
                eventListenerService.Stop();
            }

            activityLogger.LogChange("Lockdown Mode", lockdownEnabled ? "Enabled" : "Disabled");
            if (!lockdownEnabled)
            {
                ReenableMfwRules();
                activityLogger.LogDebug("All MFW rules re-enabled upon disabling Lockdown mode.");
            }
        }

        private bool ManageWslRules(bool enable)
        {
            // SharedAccess (ICS)
            if (!ManageSystemRule(
                "Minimal Firewall System - WSL Relay (ICS)",
                "Allows Internet Connection Sharing for WSL2/Hyper-V.",
                "svchost.exe",
                "SharedAccess",
                SystemFirewallRuleProtocol.Any,
                "*", "*",
                enable))
            {
                return false;
            }

            // System (PID 4)
            if (!ManageSystemRule(
                "Minimal Firewall System - Kernel/Hyper-V",
                "Allows the System process (PID 4) for WSL2 vSwitch traffic.",
                "System",
                "",
                SystemFirewallRuleProtocol.Any,
                "*", "*",
                enable))
            {
                return false;
            }

            // DNS Client (Dnscache)
            if (!ManageSystemRule(
                "Minimal Firewall System - DNS Client",
                "Allows Windows to resolve domain names (Essential for WSL).",
                "svchost.exe",
                "Dnscache",
                SystemFirewallRuleProtocol.Udp,
                "53", "*",
                enable))
            {
                return false;
            }

            // DNS Client (Dnscache) - TCP for DoH (443), DoT (853), and TCP/53 fallback
            if (!ManageSystemRule(
                "Minimal Firewall System - DNS Client (TCP)",
                "Allows the DNS Client (Dnscache) to use DNS-over-HTTPS, DNS-over-TLS, and TCP DNS fallback.",
                "svchost.exe",
                "Dnscache",
                SystemFirewallRuleProtocol.Tcp,
                "53,443,853", "*",
                enable))
            {
                return false;
            }

            return true;
        }

        public void ProcessPendingConnection(PendingConnectionViewModel pending, string decision, TimeSpan duration = default, bool trustPublisher = false)
        {
            if (pending == null) return;
            activityLogger.LogDebug($"Processing Pending Connection for '{pending.AppPath}'. Decision: {decision}, Duration: {duration}, Trust Publisher: {trustPublisher}");
            var shortSnoozeDuration = TimeSpan.FromSeconds(10);
            var longSnoozeDuration = TimeSpan.FromMinutes(2);
            if (trustPublisher && SignatureValidationService.IsSignatureTrusted(pending.AppPath, out var publisherName) && !string.IsNullOrEmpty(publisherName))
            {
                _whitelistService.Add(publisherName);
                activityLogger.LogChange("Publisher Whitelisted", $"Publisher '{publisherName}' was added to the whitelist.");
            }
            else if (trustPublisher)
            {
                activityLogger.LogDebug($"[Warning] Attempted to trust publisher for '{pending.AppPath}', but no publisher information could be extracted.");
            }

            eventListenerService.ClearPendingNotification(pending.AppPath, pending.Direction);
            switch (decision)
            {
                case "Allow":
                case "Block":
                    eventListenerService.SnoozeNotificationsForApp(pending.AppPath, shortSnoozeDuration);
                    string action = (decision == "Allow" ? "Allow" : "Block") + " (" + pending.Direction + ")";
                    if (!string.IsNullOrEmpty(pending.ServiceName))
                    {
                        var serviceNames = pending.ServiceName.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries);
                        foreach (var serviceName in serviceNames)
                        {
                            ApplyServiceRuleChange(serviceName, action, pending.AppPath);
                        }
                    }
                    else if (!string.IsNullOrEmpty(pending.AppPath))
                    {
                        ApplyApplicationRuleChange([pending.AppPath], action);
                    }
                    break;
                case "TemporaryAllow":
                    eventListenerService.SnoozeNotificationsForApp(pending.AppPath, shortSnoozeDuration);
                    CreateTemporaryAllowRule(pending.AppPath, pending.ServiceName, pending.Direction, duration);
                    break;

                case "Ignore":
                    eventListenerService.SnoozeNotificationsForApp(pending.AppPath, longSnoozeDuration);
                    activityLogger.LogDebug($"Ignored Connection: {pending.Direction} for {pending.AppPath}");
                    break;
            }
        }

        public void ReenableMfwRules()
        {
            var result = _ruleQueryBackend.EnableMfwRules();
            if (!result.Succeeded)
            {
                LogQueryFailure(result, "ReenableMfwRules failed.");
                return;
            }

            LogRuleFailures(result, "Enable rule");
        }

        private void SetupRuleTimer(string ruleName, TimeSpan duration)
        {
            var timer = new System.Threading.Timer(_ =>
            {
                try
                {
                    var result = _ruleLifecycleBackend.DeleteByName([ruleName]);
                    if (!result.Succeeded)
                    {
                        LogLifecycleFailure(result, $"Deleting temporary rule {ruleName} failed.");
                        return;
                    }

                    _temporaryRuleManager.Remove(ruleName);
                    if (_temporaryRuleTimers.TryRemove(ruleName, out var t))
                    {
                        t.Dispose();
                    }
                    activityLogger.LogDebug($"Temporary rule {ruleName} expired and was removed.");
                }
                catch (Exception ex)
                {
                    activityLogger.LogException($"Deleting temporary rule {ruleName}", ex);
                }
            }, null, duration, Timeout.InfiniteTimeSpan);
            _temporaryRuleTimers[ruleName] = timer;
        }

        private void CreateTemporaryAllowRule(string appPath, string serviceName, string direction, TimeSpan duration)
        {
            if (!ParseActionString($"Allow ({direction})", out Actions parsedAction, out Directions parsedDirection))
            {
                return;
            }

            string baseName = !string.IsNullOrEmpty(serviceName) ? serviceName.Split(',')[0].Trim() : Path.GetFileNameWithoutExtension(appPath);
            string guid = Guid.NewGuid().ToString();
            string description = "Temporarily allowed by Minimal Firewall.";
            DateTime expiry = DateTime.UtcNow.Add(duration);

            if (!string.IsNullOrEmpty(serviceName))
            {
                ProcessTcpAndUdpRules(parsedDirection, (dir, proto, suffix) =>
                {
                    string dirStr = dir == Directions.Incoming ? "In" : "Out";
                    // Added "MFW - " prefix so the timer and rule manager track the exact firewall rule name
                    string ruleName = $"MFW - Temp Allow - {baseName} - {dirStr} - {guid}{suffix}";
                    CreateServiceRule(ruleName, serviceName, dir, parsedAction, proto, appPath);
                    _temporaryRuleManager.Add(ruleName, expiry);
                    SetupRuleTimer(ruleName, duration);
                });
                activityLogger.LogChange("Temporary Rule Created", $"Allowed {baseName} (service) for {duration.TotalMinutes} minutes.");
            }
            else
            {
                // Added "MFW - " prefix 
                string ruleName = $"MFW - Temp Allow - {baseName} - {direction} - {guid}";
                CreateApplicationRule(ruleName, appPath, parsedDirection, parsedAction, ProtocolTypes.Any.Value, description);

                _temporaryRuleManager.Add(ruleName, expiry);
                SetupRuleTimer(ruleName, duration);
                activityLogger.LogChange("Temporary Rule Created", $"Allowed {baseName} ({appPath}) for {duration.TotalMinutes} minutes.");
            }
        }

        private void ProcessForeignRule(FirewallRuleChange change, bool enable, string logAction)
        {
            if (change.Rule is { Name: string ruleName })
            {
                var result = enable
                    ? _ruleLifecycleBackend.EnableByName(ruleName)
                    : _ruleLifecycleBackend.DisableByName(ruleName);

                if (!result.Succeeded)
                {
                    LogLifecycleFailure(result, $"Foreign Rule {logAction} failed for '{ruleName}'.");
                    return;
                }

                activityLogger.LogChange($"Foreign Rule {logAction}", ruleName);
                activityLogger.LogDebug($"Sentry: {logAction} foreign rule '{ruleName}'");
            }
        }

        public void AcceptForeignRule(FirewallRuleChange change) =>
            ProcessForeignRule(change, true, "Accepted");
        public void EnableForeignRule(FirewallRuleChange change) =>
            ProcessForeignRule(change, true, "Enabled");
        public void DisableForeignRule(FirewallRuleChange change) =>
            ProcessForeignRule(change, false, "Disabled");


        public void DeleteForeignRule(FirewallRuleChange change)
        {
            if (change.Rule is { Name: string ruleName })
            {
                activityLogger.LogDebug($"Sentry: Deleting foreign rule '{ruleName}'");
                DeleteAdvancedRules([ruleName]);
            }
        }

        public void SetGroupEnabledState(string groupName, bool isEnabled)
        {
            var result = _ruleQueryBackend.SetGroupEnabled(groupName, isEnabled);
            if (!result.Succeeded)
            {
                LogQueryFailure(result, $"SetGroupEnabledState failed for group '{groupName}'.");
                return;
            }

            LogRuleFailures(result, "SetGroupEnabledState for rule");
            activityLogger.LogChange("Group State Changed", $"Group '{groupName}' {(isEnabled ? "Enabled" : "Disabled")}");
        }

        public void AcceptAllForeignRules(List<FirewallRuleChange> changes)
        {
            if (changes == null || changes.Count == 0)
            {
                return;
            }

            int accepted = 0;
            foreach (var change in changes)
            {
                if (change?.Rule?.Name is not null)
                {
                    ProcessForeignRule(change, true, "Accepted");
                    accepted++;
                }
            }

            if (accepted != 0)
            {
                activityLogger.LogDebug($"Sentry: Accepted all {accepted} foreign rules.");
            }
        }

        public void CreateAdvancedRule(AdvancedRuleViewModel vm, string interfaceTypes, string icmpTypesAndCodes)
        {
            if (vm == null)
            {
                return;
            }

            // MFW prefix to protect custom rules
            if (!string.IsNullOrWhiteSpace(vm.Name) && !vm.Name.StartsWith("MFW - ", StringComparison.OrdinalIgnoreCase))
            {
                vm.Name = $"MFW - {vm.Name}";
            }

            if (!string.IsNullOrWhiteSpace(vm.ApplicationName))
            {
                vm.ApplicationName = PathResolver.NormalizePath(vm.ApplicationName);
                if (!File.Exists(vm.ApplicationName) && !vm.ApplicationName.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase) && !vm.ApplicationName.Contains("SystemApps", StringComparison.OrdinalIgnoreCase))
                {
                    activityLogger.LogDebug($"[Validation] Aborted creating advanced rule due to non-existent path: {vm.ApplicationName}");
                    return;
                }
            }

            if (vm.Status == "Allow" && !string.IsNullOrWhiteSpace(vm.ApplicationName))
            {
                FindAndQueueDeleteForGeneralBlockRule(vm.ApplicationName);
            }

            // API: rule must have exactly one direction, must create two rules if user selects "both" 
            var directionsToCreate = new List<Directions>();
            if (vm.Direction.HasFlag(Directions.Incoming))
            {
                directionsToCreate.Add(Directions.Incoming);
            }

            if (vm.Direction.HasFlag(Directions.Outgoing))
            {
                directionsToCreate.Add(Directions.Outgoing);
            }

            List<int> protocolsToCreate = [vm.Protocol];

            var errors = new List<string>();
            int successCount = 0;

            // Execute Batch
            foreach (var direction in directionsToCreate)
            {
                foreach (var protocol in protocolsToCreate)
                {
                    var ruleVm = new AdvancedRuleViewModel
                    {
                        Name = vm.Name,
                        Status = vm.Status,
                        IsEnabled = vm.IsEnabled,
                        Description = vm.Description,
                        Grouping = vm.Grouping,
                        ApplicationName = vm.ApplicationName,
                        ServiceName = vm.ServiceName,
                        LocalPorts = vm.LocalPorts,
                        RemotePorts = vm.RemotePorts,
                        LocalAddresses = vm.LocalAddresses,
                        RemoteAddresses = vm.RemoteAddresses,
                        Profiles = vm.Profiles,
                        Type = vm.Type,
                        Direction = direction,
                        Protocol = protocol,
                        InterfaceTypes = vm.InterfaceTypes,
                        IcmpTypesAndCodes = vm.IcmpTypesAndCodes
                    };

                    string nameSuffix = "";

                    if (directionsToCreate.Count > 1)
                    {
                        nameSuffix += $" - {direction}";
                    }

                    if (protocolsToCreate.Count > 1)
                    {
                        nameSuffix += (protocol == ProtocolTypes.TCP.Value) ? " - TCP" : " - UDP";
                    }

                    if (!ruleVm.Name.EndsWith(nameSuffix))
                    {
                        ruleVm.Name += nameSuffix;
                    }

                    try
                    {
                        CreateSingleAdvancedRule(ruleVm, interfaceTypes, icmpTypesAndCodes);
                        successCount++;
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Rule '{ruleVm.Name}': {ex.Message}");
                    }
                }
            }

            if (errors.Count > 0)
            {
                string msg = $"Created {successCount} rules successfully.\n\nFailed to create {errors.Count} rules:\n" + string.Join("\n", errors.Take(5));
                if (errors.Count > 5)
                {
                    msg += $"\n...and {errors.Count - 5} more.";
                }

                ShowBatchCreationErrors(msg);
            }
        }

        private void CreateSingleAdvancedRule(AdvancedRuleViewModel vm, string interfaceTypes, string icmpTypesAndCodes)
        {
            var definition = FirewallRuleCreationMapper.FromViewModel(vm, interfaceTypes, icmpTypesAndCodes);
            var result = _ruleCreationBackend.CreateRule(definition);

            if (result.Succeeded)
            {
                activityLogger.LogChange("Advanced Rule Created", vm.Name);
                return;
            }

            if (result.Exception is not null)
            {
                activityLogger.LogException(
                    $"CreateSingleAdvancedRule failed for '{vm.Name}'",
                    result.Exception);
            }
            else
            {
                activityLogger.LogDebug(
                    $"CreateSingleAdvancedRule failed for '{vm.Name}': {result.Error}");
            }

            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(result.Error)
                    ? "Firewall rule creation failed."
                    : result.Error,
                result.Exception);
        }

        public static bool ParseActionString(string action, out Actions parsedAction, out Directions parsedDirection)
        {
            parsedAction = Actions.Allow;
            parsedDirection = 0;
            if (string.IsNullOrEmpty(action))
            {
                return false;
            }

            parsedAction = action.StartsWith("Allow", StringComparison.OrdinalIgnoreCase) ? Actions.Allow : Actions.Block;
            if (action.Contains("(All)"))
            {
                parsedDirection = Directions.Incoming |
                Directions.Outgoing;
            }
            else
            {
                if (action.Contains("Inbound") || action.Contains("Incoming"))
                {
                    parsedDirection |= Directions.Incoming;
                }
                if (action.Contains("Outbound") || action.Contains("Outgoing"))
                {
                    parsedDirection |= Directions.Outgoing;
                }
            }

            if (parsedDirection == 0)
            {
                parsedDirection = Directions.Outgoing;
            }

            return true;
        }

        private static void ApplyRuleAction(string appName, string action, Action<string, Directions, Actions> createRule)
        {
            if (!ParseActionString(action, out Actions parsedAction, out Directions parsedDirection))
            {
                return;
            }

            bool bothDirs = parsedDirection.HasFlag(Directions.Incoming) && parsedDirection.HasFlag(Directions.Outgoing);

            if (parsedDirection.HasFlag(Directions.Incoming))
            {
                createRule(bothDirs ? $"{appName} - Inbound" : appName, Directions.Incoming, parsedAction);
            }
            if (parsedDirection.HasFlag(Directions.Outgoing))
            {
                createRule(bothDirs ? $"{appName} - Outbound" : appName, Directions.Outgoing, parsedAction);
            }
        }

        private void BuildAndCreateRule(string name, string description, string grouping, Directions direction, Actions action, int protocol, string appPath, string serviceName, RuleType ruleType)
        {
            // MFW prefix to protect against OS overwrites
            string safeName = (name ?? string.Empty).StartsWith("MFW - ", StringComparison.OrdinalIgnoreCase) ?
                (name ?? string.Empty) : $"MFW - {name}";

            var vm = new AdvancedRuleViewModel
            {
                Name = safeName,
                Description = description,
                IsEnabled = true,
                Grouping = grouping,
                Status = action == Actions.Allow ? "Allow" : "Block",
                Direction = direction,
                Protocol = protocol,
                ApplicationName = appPath ?? "",
                ServiceName = serviceName ?? "",
                LocalPorts = "*",
                RemotePorts = "*",
                LocalAddresses = "*",
                RemoteAddresses = "*",
                Profiles = "All",
                Type = ruleType,
                InterfaceTypes = "All",
                IcmpTypesAndCodes = ""
            };

            CreateSingleAdvancedRule(vm, "All", "");
        }

        private void CreateApplicationRule(string name, string appPath, Directions direction, Actions action, int protocol, string description)
        {
            activityLogger.LogDebug($"Creating Application Rule: '{name}' for '{appPath}'");
            string grouping = (!string.IsNullOrEmpty(description) && description.StartsWith(MFWConstants.WildcardDescriptionPrefix, StringComparison.OrdinalIgnoreCase))
                ? MFWConstants.WildcardRuleGroup : MFWConstants.MainRuleGroup;
            BuildAndCreateRule(name, description, grouping, direction, action, protocol, appPath, "", RuleType.Program);
        }

        private void CreateServiceRule(string name, string serviceName, Directions direction, Actions action, int protocol, string? appPath = null)
        {
            activityLogger.LogDebug($"Creating Service Rule: '{name}' for service '{serviceName}' with AppPath: '{appPath ?? "null"}'");
            BuildAndCreateRule(name, "", MFWConstants.MainRuleGroup, direction, action, protocol, appPath!, serviceName, RuleType.Service);
        }

        private void CreateUwpRule(string name, string packageFamilyName, Directions direction, Actions action, int protocol)
        {
            activityLogger.LogDebug($"Creating UWP Rule: '{name}' for PFN '{packageFamilyName}'");
            BuildAndCreateRule(name, MFWConstants.UwpDescriptionPrefix + packageFamilyName, MFWConstants.MainRuleGroup, direction, action, protocol, "", "", RuleType.UWP);
        }

        public async Task DeleteGroupAsync(string groupName)
        {
            await Task.Run(() =>
            {
                activityLogger.LogDebug($"Deleting all rules in group: {groupName}");
                var result = _ruleLifecycleBackend.DeleteByGroup(groupName);
                if (!result.Succeeded)
                {
                    LogLifecycleFailure(result, $"DeleteGroupAsync failed for {groupName}.");
                }
            });
        }

        public void DeleteAllMfwRules()
        {
            var result = _ruleLifecycleBackend.DeleteAllMfwRules();
            if (!result.Succeeded)
            {
                LogLifecycleFailure(result, "DeleteAllMfwRules failed.");
                return;
            }

            _wildcardRuleService.ClearRules();
            activityLogger.LogChange("Bulk Delete", "All Minimal Firewall rules deleted by user.");
        }

        public void UpdateWildcardRule(WildcardRule oldRule, WildcardRule newRule)
        {
            _wildcardRuleService.UpdateRule(oldRule, newRule);
            DeleteRulesForWildcard(oldRule);
            activityLogger.LogChange("Wildcard Rule Updated", newRule.FolderPath);
        }

        public void RemoveWildcardRule(WildcardRule rule)
        {
            _wildcardRuleService.RemoveRule(rule);
            DeleteRulesForWildcard(rule);
            activityLogger.LogChange("Wildcard Rule Removed", rule.FolderPath);
        }

        public void RemoveWildcardDefinitionOnly(WildcardRule rule)
        {
            _wildcardRuleService.RemoveRule(rule);
            activityLogger.LogChange("Wildcard Definition Removed", rule.FolderPath);
        }

        public void ApplyWildcardMatch(string appPath, string serviceName, WildcardRule rule)
        {
            if (!ParseActionString(rule.Action, out Actions parsedAction, out Directions parsedDirection))
            {
                activityLogger.LogDebug($"[ApplyWildcardMatch] Invalid action string in wildcard rule for {rule.FolderPath}: {rule.Action}");
                return;
            }

            void createRule(string baseName, Directions dir, Actions act, int protocol, string? serviceNameToUse)
            {
                if (!ValidationUtility.ValidatePortString(rule.LocalPorts, out string localPortError))
                {
                    activityLogger.LogDebug($"[ApplyWildcardMatch] Invalid LocalPorts '{rule.LocalPorts}' in wildcard for {rule.FolderPath}. Rule '{baseName}' not created. Error: {localPortError}");
                    return;
                }
                if (!ValidationUtility.ValidatePortString(rule.RemotePorts, out string remotePortError))
                {
                    activityLogger.LogDebug($"[ApplyWildcardMatch] Invalid RemotePorts '{rule.RemotePorts}' in wildcard for {rule.FolderPath}. Rule '{baseName}' not created. Error: {remotePortError}");
                    return;
                }
                if (!ValidationUtility.ValidateAddressString(rule.RemoteAddresses, out string remoteAddressError))
                {
                    activityLogger.LogDebug($"[ApplyWildcardMatch] Invalid RemoteAddresses '{rule.RemoteAddresses}' in wildcard for {rule.FolderPath}. Rule '{baseName}' not created. Error: {remoteAddressError}");
                    return;
                }

                // MFW prefix to protect wildcard generated rules
                string safeName = baseName.StartsWith("MFW - ", StringComparison.OrdinalIgnoreCase) ? baseName : $"MFW - {baseName}";

                var vm = new AdvancedRuleViewModel
                {
                    Name = safeName,
                    ApplicationName = string.IsNullOrEmpty(serviceNameToUse) ? appPath : "",
                    ServiceName = !string.IsNullOrEmpty(serviceNameToUse) ? serviceNameToUse : "",
                    Direction = dir,
                    Status = act == Actions.Allow ? "Allow" : "Block",
                    IsEnabled = true,
                    Grouping = MFWConstants.WildcardRuleGroup,
                    Description = $"{MFWConstants.WildcardDescriptionPrefix}{rule.FolderPath}]",
                    Protocol = protocol,
                    LocalPorts = (protocol == 6 || protocol == 17) ? (string.IsNullOrEmpty(rule.LocalPorts) ? "*" : rule.LocalPorts) : "*",
                    RemotePorts = (protocol == 6 || protocol == 17) ? (string.IsNullOrEmpty(rule.RemotePorts) ? "*" : rule.RemotePorts) : "*",
                    LocalAddresses = "*",
                    RemoteAddresses = string.IsNullOrEmpty(rule.RemoteAddresses) ? "*" : rule.RemoteAddresses,
                    Profiles = "All",
                    Type = RuleType.Wildcard,
                    InterfaceTypes = "All",
                    IcmpTypesAndCodes = ""
                };

                try
                {
                    CreateSingleAdvancedRule(vm, "All", "");
                    activityLogger.LogDebug($"[ApplyWildcardMatch] Successfully created rule '{baseName}' from wildcard match.");
                }
                catch (Exception ex)
                {
                    activityLogger.LogException($"ApplyWildcardMatch-CreateRule-{baseName}", ex);
                }
            }

            var serviceNames = serviceName.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries);
            bool isSvcHost = Path.GetFileName(appPath).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
            string appNameBase = Path.GetFileNameWithoutExtension(appPath);

            List<string?> servicesToCreateRulesFor;
            if (serviceNames.Length > 0)
            {
                servicesToCreateRulesFor = [.. serviceNames];
            }
            else if (isSvcHost)
            {
                servicesToCreateRulesFor = ["*"];
            }
            else
            {
                servicesToCreateRulesFor = [null];
            }

            foreach (var sName in servicesToCreateRulesFor)
            {
                string ruleNameBase = string.IsNullOrEmpty(sName) ?
                appNameBase : (sName == "*" ? appNameBase : sName);

                if (rule.Protocol == ProtocolTypes.Any.Value)
                {
                    string actionStr = parsedAction == Actions.Allow ? "" : "Block ";
                    ProcessTcpAndUdpRules(parsedDirection, (dir, proto, suffix) =>
                    {
                        string dirStr = dir == Directions.Incoming ? "In" : "Out";
                        createRule($"{ruleNameBase} - {actionStr}{dirStr}{suffix}", dir, parsedAction, proto, sName);
                    });
                }
                else
                {
                    ApplyRuleAction(ruleNameBase, rule.Action, (name, dir, act) => createRule(name, dir, act, rule.Protocol, sName));
                }
            }

            activityLogger.LogChange("Wildcard Rule Applied", rule.Action + " for " + appPath);
        }

        public async Task<List<string>> CleanUpOrphanedRulesAsync(CancellationToken token, IProgress<int>? progress = null)
        {
            var orphanedRuleNames = new List<string>();
            var query = _ruleQueryBackend.GetMfwRules();
            if (!query.Succeeded || query.Value is null)
            {
                LogQueryFailure(query, "CleanUpOrphanedRulesAsync failed to enumerate rules.");
                return orphanedRuleNames;
            }

            // Rules whose properties could not be read are skipped, as before.
            var mfwRulesData = query.Value
                .Select(r => (Name: r.Name, ApplicationName: r.ApplicationName))
                .ToList();

            int total = mfwRulesData.Count;
            if (total == 0)
            {
                progress?.Report(100);
                return orphanedRuleNames;
            }

            int processed = 0;

            // Execute safe, COM-free validation on the background thread
            await Task.Run(() =>
            {
                foreach (var (Name, ApplicationName) in mfwRulesData)
                {
                    if (token.IsCancellationRequested)
                    {
                        break;
                    }

                    string appPath = ApplicationName;

                    if (!string.IsNullOrEmpty(appPath) && appPath != "*" && !appPath.StartsWith('@'))
                    {
                        string expandedPath = Environment.ExpandEnvironmentVariables(appPath);
                        if (!File.Exists(expandedPath) && !expandedPath.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase) && !expandedPath.Contains("SystemApps", StringComparison.OrdinalIgnoreCase))
                        {
                            orphanedRuleNames.Add(Name);
                            activityLogger.LogDebug($"Found orphaned rule '{Name}' for path: {expandedPath}");
                        }
                    }

                    processed++;
                    progress?.Report((processed * 100) / total);
                }
            }, token);

            if (token.IsCancellationRequested)
            {
                return [];
            }

            if (orphanedRuleNames.Count != 0)
            {
                activityLogger.LogDebug($"Deleting {orphanedRuleNames.Count} orphaned rules.");
                var deleteResult = _ruleLifecycleBackend.DeleteByName(orphanedRuleNames);
                if (!deleteResult.Succeeded)
                {
                    LogLifecycleFailure(deleteResult, "CleanUpOrphanedRulesAsync (Deletion) failed.");
                }
                else
                {
                    activityLogger.LogChange("Orphaned Rules Cleaned", $"{orphanedRuleNames.Count} rules deleted.");
                }
            }

            return orphanedRuleNames;
        }

        public async Task<string> ExportAllMfwRulesAsync()
        {
            var advancedRules = await _dataService.GetAggregatedRulesAsync(CancellationToken.None);
            var portableAdvancedRules = advancedRules.SelectMany(ar => ar.UnderlyingRules ?? [])
                .OfType<AdvancedRuleViewModel>()
                .Select(static rule =>
                {
                    rule.ApplicationName = PathResolver.ConvertToEnvironmentPath(rule.ApplicationName);
                    return rule;
                }).ToList();
            var wildcardRules = _wildcardRuleService.GetRules()
                .Select(r =>
                {
                    r.FolderPath = PathResolver.ConvertToEnvironmentPath(r.FolderPath);
                    return r;
                }).ToList();
            var container = new ExportContainer
            {
                ExportDate = DateTime.UtcNow,
                AdvancedRules = portableAdvancedRules,
                WildcardRules = wildcardRules
            };
            return JsonSerializer.Serialize(container, ExportContainerJsonContext.Default.ExportContainer);
        }

        public async Task ImportRulesAsync(string jsonContent, bool replace)
        {
            if (!EnqueueImportTasks(jsonContent, replace, out int advancedCount, out int wildcardCount))
            {
                return;
            }

            // Wait for the queue to drain
            await BackgroundTaskService!.WhenIdleAsync();

            activityLogger.LogChange("Rules Imported", $"Imported {advancedCount} advanced rules and {wildcardCount} wildcard rules. Replace: {replace}");
        }

        // Enqueues the individual import tasks without waiting for them. The queue
        // handler for ImportRules must use this instead of ImportRulesAsync: awaiting
        // WhenIdleAsync from inside a handler deadlocks the single worker on its own
        // queue (the handler counts as outstanding work until it returns).
        public bool EnqueueImportTasks(string jsonContent, bool replace, out int advancedCount, out int wildcardCount)
        {
            advancedCount = 0;
            wildcardCount = 0;

            if (BackgroundTaskService == null)
            {
                activityLogger.LogDebug("[Import] BackgroundTaskService is not available.");
                return false;
            }

            try
            {
                var container = JsonSerializer.Deserialize(jsonContent, ExportContainerJsonContext.Default.ExportContainer);
                if (container == null)
                {
                    activityLogger.LogDebug("[Import] Failed to deserialize JSON content.");
                    return false;
                }

                if (replace)
                {
                    BackgroundTaskService.EnqueueTask(new FirewallTask(FirewallTaskType.DeleteAllMfwRules, new object()));
                }

                foreach (var ruleVm in container.AdvancedRules ?? [])
                {
                    if (ruleVm == null) continue;
                    ruleVm.ApplicationName = PathResolver.ConvertFromEnvironmentPath(ruleVm.ApplicationName);
                    var payload = new CreateAdvancedRulePayload { ViewModel = ruleVm, InterfaceTypes = ruleVm.InterfaceTypes, IcmpTypesAndCodes = ruleVm.IcmpTypesAndCodes };
                    BackgroundTaskService.EnqueueTask(new FirewallTask(FirewallTaskType.CreateAdvancedRule, payload));
                    advancedCount++;
                }

                foreach (var wildcardRule in container.WildcardRules ?? [])
                {
                    wildcardRule.FolderPath = PathResolver.ConvertFromEnvironmentPath(wildcardRule.FolderPath);
                    BackgroundTaskService.EnqueueTask(new FirewallTask(FirewallTaskType.AddWildcardRule, wildcardRule));
                    wildcardCount++;
                }

                return true;
            }
            catch (JsonException ex)
            {
                activityLogger.LogException("ImportRules", ex);
                return false;
            }
        }
    }
}
