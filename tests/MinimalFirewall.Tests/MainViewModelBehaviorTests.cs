using Firewall.Traffic.ViewModels;
using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class MainViewModelBehaviorTests
{
    [Fact]
    public async Task RefreshRulesDataAsync_LoadsRulesAndApplyRulesFiltersRaisesUpdateEvent()
    {
        using var scope = new MainViewModelTestScope();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(
            Snapshot("Demo App", MFWConstants.MainRuleGroup, @"C:\Apps\demo.exe"),
            Snapshot("Windows System Rule", "Windows Firewall", "*"));

        var dataService = scope.CreateDataService(backend);
        using var viewModel = scope.CreateViewModel(dataService);

        var progress = new RecordingProgress();
        await viewModel.RefreshRulesDataAsync(CancellationToken.None, progress);

        Assert.Equal(2, viewModel.AllAggregatedRules.Count);
        Assert.Equal(100, progress.LastValue);

        int updates = 0;
        viewModel.RulesListUpdated += () => updates++;

        viewModel.ApplyRulesFilters(
            searchText: string.Empty,
            enabledTypes: [],
            showSystemRules: false);

        var visibleRule = Assert.Single(viewModel.VirtualRulesData);
        Assert.Equal("Demo App", visibleRule.Name);
        Assert.Equal(1, updates);
    }

    [Fact]
    public async Task ApplyRulesFilters_CombinesTypeAndSearchFilters()
    {
        using var scope = new MainViewModelTestScope();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(
            Snapshot("Demo Program", MFWConstants.MainRuleGroup, @"C:\Apps\demo.exe"),
            Snapshot("Other Program", MFWConstants.MainRuleGroup, @"C:\Apps\other.exe"),
            Snapshot("DNS Service", MFWConstants.MainRuleGroup, "*", serviceName: "Dnscache"));

        var dataService = scope.CreateDataService(backend);
        using var viewModel = scope.CreateViewModel(dataService);
        await viewModel.RefreshRulesDataAsync(CancellationToken.None);

        viewModel.ApplyRulesFilters(
            searchText: "demo",
            enabledTypes: [RuleType.Program],
            showSystemRules: false);

        var filtered = Assert.Single(viewModel.VirtualRulesData);
        Assert.Equal("Demo Program", filtered.Name);
        Assert.Equal(RuleType.Program, filtered.Type);
    }

    [Fact]
    public void AddPendingConnection_DoesNotAddDuplicateApplicationPath()
    {
        using var scope = new MainViewModelTestScope();
        using var viewModel = scope.CreateViewModel(dataService: null!);

        var first = new PendingConnectionViewModel
        {
            AppPath = @"C:\Apps\client.exe",
            Direction = "Outgoing"
        };
        var duplicate = new PendingConnectionViewModel
        {
            AppPath = @"c:\apps\CLIENT.EXE",
            Direction = "Incoming"
        };

        viewModel.AddPendingConnection(first);
        viewModel.AddPendingConnection(duplicate);

        Assert.Same(first, Assert.Single(viewModel.PendingConnections));
    }

    [Fact]
    public void AddPendingConnection_BlockedWildcardMatchIsNotAddedToDashboard()
    {
        using var scope = new MainViewModelTestScope();
        scope.WildcardRules.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Apps",
            ExeName = "*.exe",
            Action = "Block"
        });
        using var viewModel = scope.CreateViewModel(dataService: null!);

        viewModel.AddPendingConnection(new PendingConnectionViewModel
        {
            AppPath = @"C:\Apps\blocked.exe",
            Direction = "Outgoing"
        });

        Assert.Empty(viewModel.PendingConnections);
    }

    [Fact]
    public async Task ClearRulesData_ClearsBothCollectionsAndInvalidatesDataCache()
    {
        using var scope = new MainViewModelTestScope();
        var backend = new InMemoryFirewallBackend();
        backend.Seed(Snapshot("Demo App", MFWConstants.MainRuleGroup, @"C:\Apps\demo.exe"));

        var dataService = scope.CreateDataService(backend);
        using var viewModel = scope.CreateViewModel(dataService);
        await viewModel.RefreshRulesDataAsync(CancellationToken.None);
        viewModel.ApplyRulesFilters(string.Empty, [], showSystemRules: true);

        int updates = 0;
        viewModel.RulesListUpdated += () => updates++;

        viewModel.ClearRulesData();

        Assert.Empty(viewModel.AllAggregatedRules);
        Assert.Empty(viewModel.VirtualRulesData);
        Assert.Equal(1, updates);

        await viewModel.RefreshRulesDataAsync(CancellationToken.None);

        Assert.Single(viewModel.AllAggregatedRules);
        Assert.Equal(2, backend.SnapshotQueryCalls);
    }

    private static FirewallRuleSnapshot Snapshot(
        string name,
        string grouping,
        string applicationName,
        string serviceName = "")
        => new(
            name,
            "Test rule description",
            true,
            (int)Directions.Outgoing,
            false,
            6,
            applicationName,
            serviceName,
            "*",
            "*",
            "*",
            "*",
            0x7FFFFFFF,
            grouping,
            "All",
            string.Empty);

    private sealed class RecordingProgress : IProgress<int>
    {
        public int LastValue { get; private set; }
        public void Report(int value) => LastValue = value;
    }

    private sealed class MainViewModelTestScope : IDisposable
    {
        private readonly string _directory =
            Path.Combine(Path.GetTempPath(), $"mfw-mainvm-tests-{Guid.NewGuid():N}");

        public WildcardRuleService WildcardRules { get; }

        public MainViewModelTestScope()
        {
            Directory.CreateDirectory(_directory);
            WildcardRules = new WildcardRuleService(Path.Combine(_directory, "wildcard_rules.json"));
        }

        public FirewallDataService CreateDataService(InMemoryFirewallBackend backend)
            => new(
                WildcardRules,
                new UwpService(Path.Combine(_directory, "uwp_apps.json")),
                new RuleTimestampService(Path.Combine(_directory, "timestamps.json")),
                backend);

        public MainViewModel CreateViewModel(FirewallDataService dataService)
            => new(
                ruleUpdateBackend: null!,
                wildcardRuleService: WildcardRules,
                backgroundTaskService: null!,
                dataService: dataService,
                firewallSentryService: null!,
                trafficMonitorViewModel: new TrafficMonitorViewModel(),
                eventListenerService: null!,
                appSettings: null!,
                activityLogger: null!,
                actionsService: null!,
                startBackgroundServices: false);

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
