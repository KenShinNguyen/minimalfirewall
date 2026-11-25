using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class RuleCommandCoordinatorTests
{
    [Fact]
    public async Task EnqueueCreateAdvancedRule_QueuesAndDrainsCreateCommand()
    {
        using var scope = new RuleCommandCoordinatorTestScope();
        using var backgroundTasks = scope.CreateBackgroundTaskService();
        var coordinator = new RuleCommandCoordinator(backgroundTasks);

        var viewModel = new AdvancedRuleViewModel
        {
            Name = "Coordinator Test Rule",
            Status = "Block",
            IsEnabled = true,
            Direction = Directions.Outgoing,
            Protocol = 256,
            ApplicationName = string.Empty,
            ServiceName = string.Empty,
            LocalPorts = "*",
            RemotePorts = "*",
            LocalAddresses = "*",
            RemoteAddresses = "*",
            Profiles = "All",
            Description = "Created by RuleCommandCoordinator test",
            Grouping = "Coordinator Tests - MFW",
            InterfaceTypes = "All",
            IcmpTypesAndCodes = string.Empty
        };

        coordinator.EnqueueCreateAdvancedRule(viewModel, "All", string.Empty);

        await backgroundTasks.WhenIdleAsync();

        var created = Assert.Single(scope.Backend.Rules);
        Assert.Equal("MFW - Coordinator Test Rule", created.Name);
        Assert.Contains("CreateRule:MFW - Coordinator Test Rule", scope.Backend.Operations);
    }

    [Fact]
    public async Task EnqueueApplyApplicationRule_QueuesAndDrainsApplicationCommand()
    {
        using var scope = new RuleCommandCoordinatorTestScope();
        using var backgroundTasks = scope.CreateBackgroundTaskService();
        var coordinator = new RuleCommandCoordinator(backgroundTasks);

        coordinator.EnqueueApplyApplicationRule(
            @"C:\Apps\coordinator-test.exe",
            "Allow");

        await backgroundTasks.WhenIdleAsync();

        Assert.Contains(
            scope.Backend.Operations,
            operation => operation.Contains("ApplyApplicationRule", StringComparison.Ordinal));
    }

    private sealed class RuleCommandCoordinatorTestScope : IDisposable
    {
        private readonly string _directory =
            Path.Combine(Path.GetTempPath(), $"mfw-rule-command-tests-{Guid.NewGuid():N}");

        public InMemoryFirewallBackend Backend { get; } = new();
        public WildcardRuleService WildcardRules { get; }

        public RuleCommandCoordinatorTestScope()
        {
            Directory.CreateDirectory(_directory);
            WildcardRules = new WildcardRuleService(
                Path.Combine(_directory, "wildcard_rules.json"));
        }

        public BackgroundFirewallTaskService CreateBackgroundTaskService()
        {
            var dataService = new FirewallDataService(
                WildcardRules,
                new UwpService(Path.Combine(_directory, "uwp_apps.json")),
                new RuleTimestampService(Path.Combine(_directory, "timestamps.json")),
                Backend);

            var actionsService = new FirewallActionsService(
                new UserActivityLogger(),
                null!,
                null!,
                null!,
                WildcardRules,
                dataService,
                Backend,
                Backend,
                Backend,
                Backend,
                Backend);

            return new BackgroundFirewallTaskService(
                actionsService,
                new UserActivityLogger(),
                WildcardRules,
                dataService);
        }

        public void Dispose()
        {
            WildcardRules.Dispose();

            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
