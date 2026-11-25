using System;
using System.Collections.Generic;

namespace MinimalFirewall
{
    /// <summary>
    /// Phase 5A mutation seam. Keeps firewall rule creation/deletion mechanics
    /// behind a focused coordinator while FirewallActionsService remains the
    /// public orchestration facade.
    /// </summary>
    internal sealed class RuleMutationCoordinator
    {
        private readonly IFirewallRuleCreationBackend _creationBackend;
        private readonly UserActivityLogger _activityLogger;

        internal RuleMutationCoordinator(
            IFirewallRuleCreationBackend creationBackend,
            UserActivityLogger activityLogger)
        {
            _creationBackend = creationBackend;
            _activityLogger = activityLogger;
        }

        internal void ExecuteRuleDeletion(
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
                _activityLogger.LogChange($"{logPrefix} Deleted", item);
            }
        }

        internal void CreateSingleAdvancedRule(
            AdvancedRuleViewModel vm,
            string interfaceTypes,
            string icmpTypesAndCodes)
        {
            var definition = FirewallRuleCreationMapper.FromViewModel(vm, interfaceTypes, icmpTypesAndCodes);
            var result = _creationBackend.CreateRule(definition);

            if (result.Succeeded)
            {
                _activityLogger.LogChange("Advanced Rule Created", vm.Name);
                return;
            }

            if (result.Exception is not null)
            {
                _activityLogger.LogException(
                    $"CreateSingleAdvancedRule failed for '{vm.Name}'",
                    result.Exception);
            }
            else
            {
                _activityLogger.LogDebug(
                    $"CreateSingleAdvancedRule failed for '{vm.Name}': {result.Error}");
            }

            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(result.Error)
                    ? "Firewall rule creation failed."
                    : result.Error,
                result.Exception);
        }

        private void LogLifecycleFailure(FirewallRuleLifecycleOperationResult result, string message)
        {
            if (result.Exception is not null)
            {
                _activityLogger.LogException(message.TrimEnd('.'), result.Exception);
                return;
            }

            _activityLogger.LogDebug(
                string.IsNullOrWhiteSpace(result.Error) ? message : $"{message} {result.Error}");
        }
    }
}
