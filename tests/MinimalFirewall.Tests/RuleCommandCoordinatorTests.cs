using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class RuleCommandCoordinatorTests
{
    [Fact]
    public void Constructor_RejectsNullDependencies()
    {
        var serviceException = Assert.Throws<ArgumentNullException>(
            () => new RuleCommandCoordinator((BackgroundFirewallTaskService)null!));
        Assert.Equal("backgroundTaskService", serviceException.ParamName);

        var enqueueException = Assert.Throws<ArgumentNullException>(
            () => new RuleCommandCoordinator((Action<FirewallTask>)null!));
        Assert.Equal("enqueueTask", enqueueException.ParamName);
    }

    [Fact]
    public void EnqueueCreateAdvancedRule_RejectsNullInputsWithoutEnqueueing()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);
        var viewModel = CreateAdvancedRuleViewModel();

        Assert.Equal(
            "viewModel",
            Assert.Throws<ArgumentNullException>(
                () => coordinator.EnqueueCreateAdvancedRule(null!, "All", string.Empty)).ParamName);

        Assert.Equal(
            "interfaceTypes",
            Assert.Throws<ArgumentNullException>(
                () => coordinator.EnqueueCreateAdvancedRule(viewModel, null!, string.Empty)).ParamName);

        Assert.Equal(
            "icmpTypesAndCodes",
            Assert.Throws<ArgumentNullException>(
                () => coordinator.EnqueueCreateAdvancedRule(viewModel, "All", null!)).ParamName);

        Assert.Empty(tasks);
    }

    [Fact]
    public void EnqueueCreateAdvancedRule_EnqueuesExpectedTypedPayloadExactlyOnce()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);
        var viewModel = CreateAdvancedRuleViewModel("Coordinator Test Rule");

        coordinator.EnqueueCreateAdvancedRule(viewModel, "All", string.Empty);

        var task = Assert.Single(tasks);
        Assert.Equal(FirewallTaskType.CreateAdvancedRule, task.TaskType);
        Assert.Equal("Creating rule: Coordinator Test Rule", task.Description);

        var payload = Assert.IsType<CreateAdvancedRulePayload>(task.Payload);
        Assert.Same(viewModel, payload.ViewModel);
        Assert.Equal("All", payload.InterfaceTypes);
        Assert.Equal(string.Empty, payload.IcmpTypesAndCodes);
    }

    [Fact]
    public void EnqueueApplyApplicationRule_RejectsNullOrWhitespacePath()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);

        Assert.Equal(
            "appPath",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule(null!, "Allow")).ParamName);
        Assert.Equal(
            "appPath",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule(string.Empty, "Allow")).ParamName);
        Assert.Equal(
            "appPath",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule("  ", "Allow")).ParamName);

        Assert.Empty(tasks);
    }

    [Fact]
    public void EnqueueApplyApplicationRule_RejectsNullOrWhitespaceAction()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);
        const string appPath = @"C:\Program Files\Contoso\app.exe";

        Assert.Equal(
            "action",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule(appPath, null!)).ParamName);
        Assert.Equal(
            "action",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule(appPath, string.Empty)).ParamName);
        Assert.Equal(
            "action",
            Assert.Throws<ArgumentException>(
                () => coordinator.EnqueueApplyApplicationRule(appPath, "  ")).ParamName);

        Assert.Empty(tasks);
    }

    [Fact]
    public void EnqueueApplyApplicationRule_EnqueuesExpectedTypedPayloadExactlyOnce()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);
        const string appPath = @"C:\Program Files\Contoso\app.exe";

        coordinator.EnqueueApplyApplicationRule(appPath, "Allow Outbound");

        var task = Assert.Single(tasks);
        Assert.Equal(FirewallTaskType.ApplyApplicationRule, task.TaskType);
        Assert.Equal("Applying Allow Outbound to app.exe", task.Description);

        var payload = Assert.IsType<ApplyApplicationRulePayload>(task.Payload);
        Assert.Equal(new[] { appPath }, payload.AppPaths);
        Assert.Equal("Allow Outbound", payload.Action);
        Assert.Null(payload.WildcardSourcePath);
        Assert.Null(payload.AutoAllowedPublisher);
    }

    [Fact]
    public void EnqueueMixedCommands_PreservesFifoOrderAndEnqueuesEachExactlyOnce()
    {
        var tasks = new List<FirewallTask>();
        var coordinator = new RuleCommandCoordinator(tasks.Add);

        coordinator.EnqueueCreateAdvancedRule(
            CreateAdvancedRuleViewModel("First"),
            "All",
            string.Empty);
        coordinator.EnqueueApplyApplicationRule(
            @"C:\Program Files\Contoso\app.exe",
            "Block Inbound");
        coordinator.EnqueueCreateAdvancedRule(
            CreateAdvancedRuleViewModel("Third"),
            "LAN",
            "8:0");

        Assert.Equal(3, tasks.Count);
        Assert.Equal(
            new[]
            {
                FirewallTaskType.CreateAdvancedRule,
                FirewallTaskType.ApplyApplicationRule,
                FirewallTaskType.CreateAdvancedRule
            },
            tasks.Select(task => task.TaskType));

        Assert.Equal(
            new[] { "Creating rule: First", "Applying Block Inbound to app.exe", "Creating rule: Third" },
            tasks.Select(task => task.Description));
    }

    [Fact]
    public async Task ProductionConstructor_EnqueuesBothCommandsAndBackgroundServiceDrainsThem()
    {
        using var scope = new RuleCommandCoordinatorTestScope();
        using var backgroundTasks = scope.CreateBackgroundTaskService();
        var coordinator = new RuleCommandCoordinator(backgroundTasks);
        const string appPath = @"C:\Program Files\WindowsApps\Contoso.App\app.exe";

        coordinator.EnqueueCreateAdvancedRule(
            CreateAdvancedRuleViewModel("Production Constructor Rule"),
            "All",
            string.Empty);
        coordinator.EnqueueApplyApplicationRule(appPath, "Allow Outbound");

        await backgroundTasks.WhenIdleAsync().WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Contains(
            scope.Backend.Rules,
            rule => rule.Name == "MFW - Production Constructor Rule");
        Assert.Contains(
            scope.Backend.Rules,
            rule => string.Equals(
                rule.ApplicationName,
                appPath,
                StringComparison.OrdinalIgnoreCase));
    }

    private static AdvancedRuleViewModel CreateAdvancedRuleViewModel(string name = "Test Rule")
        => new()
        {
            Name = name,
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
