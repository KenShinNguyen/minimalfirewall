using System;
using System.IO;

namespace MinimalFirewall
{
    /// <summary>
    /// Phase 5B command seam. Centralizes background firewall task dispatch
    /// used by MainViewModel rule commands.
    /// </summary>
    internal sealed class RuleCommandCoordinator
    {
        private readonly Action<FirewallTask> _enqueueTask;

        internal RuleCommandCoordinator(BackgroundFirewallTaskService backgroundTaskService)
        {
            ArgumentNullException.ThrowIfNull(backgroundTaskService);
            _enqueueTask = backgroundTaskService.EnqueueTask;
        }

        // Delegate overload keeps the command-construction contract independently testable.
        internal RuleCommandCoordinator(Action<FirewallTask> enqueueTask)
        {
            _enqueueTask = enqueueTask ?? throw new ArgumentNullException(nameof(enqueueTask));
        }

        internal void EnqueueCreateAdvancedRule(
            AdvancedRuleViewModel viewModel,
            string interfaceTypes,
            string icmpTypesAndCodes)
        {
            ArgumentNullException.ThrowIfNull(viewModel);
            ArgumentNullException.ThrowIfNull(interfaceTypes);
            ArgumentNullException.ThrowIfNull(icmpTypesAndCodes);

            var payload = new CreateAdvancedRulePayload
            {
                ViewModel = viewModel,
                InterfaceTypes = interfaceTypes,
                IcmpTypesAndCodes = icmpTypesAndCodes
            };

            _enqueueTask(
                new FirewallTask(
                    FirewallTaskType.CreateAdvancedRule,
                    payload,
                    $"Creating rule: {viewModel.Name}"));
        }

        internal void EnqueueApplyApplicationRule(string appPath, string action)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(appPath);
            ArgumentException.ThrowIfNullOrWhiteSpace(action);

            var payload = new ApplyApplicationRulePayload
            {
                AppPaths = [appPath],
                Action = action
            };

            _enqueueTask(
                new FirewallTask(
                    FirewallTaskType.ApplyApplicationRule,
                    payload,
                    $"Applying {action} to {Path.GetFileName(appPath)}"));
        }
    }
}
