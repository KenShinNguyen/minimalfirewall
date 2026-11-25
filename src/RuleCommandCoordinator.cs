namespace MinimalFirewall
{
    /// <summary>
    /// Phase 5B command seam. Centralizes background firewall task dispatch
    /// used by MainViewModel rule commands.
    /// </summary>
    internal sealed class RuleCommandCoordinator
    {
        private readonly BackgroundFirewallTaskService _backgroundTaskService;

        internal RuleCommandCoordinator(BackgroundFirewallTaskService backgroundTaskService)
        {
            _backgroundTaskService = backgroundTaskService;
        }

        internal void EnqueueCreateAdvancedRule(
            AdvancedRuleViewModel viewModel,
            string interfaceTypes,
            string icmpTypesAndCodes)
        {
            var payload = new CreateAdvancedRulePayload
            {
                ViewModel = viewModel,
                InterfaceTypes = interfaceTypes,
                IcmpTypesAndCodes = icmpTypesAndCodes
            };

            _backgroundTaskService.EnqueueTask(
                new FirewallTask(
                    FirewallTaskType.CreateAdvancedRule,
                    payload,
                    $"Creating rule: {viewModel.Name}"));
        }

        internal void EnqueueApplyApplicationRule(string appPath, string action)
        {
            var payload = new ApplyApplicationRulePayload
            {
                AppPaths = [appPath],
                Action = action
            };

            _backgroundTaskService.EnqueueTask(
                new FirewallTask(
                    FirewallTaskType.ApplyApplicationRule,
                    payload,
                    $"Applying {action} to {Path.GetFileName(appPath)}"));
        }
    }
}
