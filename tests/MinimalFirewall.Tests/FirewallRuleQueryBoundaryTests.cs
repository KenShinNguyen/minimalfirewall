using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
using MinimalFirewall.TypedObjects;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleQueryBoundaryTests
{
    private const string AppPath = @"C:\Apps\demo.exe";

    [Theory]
    [InlineData("My Group - MFW", true)]
    [InlineData("Minimal Firewall - MFW", true)]
    [InlineData("Minimal Firewall (Wildcard) - MFW", true)]
    [InlineData("Some Other Group", false)]
    [InlineData("Minimal Firewall", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsMfwGroup_MatchesOriginalIsMfwRuleSemantics(string? grouping, bool expected)
    {
        Assert.Equal(expected, MfwRuleGroups.IsMfwGroup(grouping));
    }

    [Theory]
    [InlineData("My Group - MFW", true)]
    [InlineData("Minimal Firewall", true)]
    [InlineData("Minimal Firewall (Wildcard)", true)]
    [InlineData("Some Other Group", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsReenableTargetGroup_KeepsLegacyGroupNames(string? grouping, bool expected)
    {
        Assert.Equal(expected, MfwRuleGroups.IsReenableTargetGroup(grouping));
    }

    [Fact]
    public void AdvancedRuleViewModelMapping_ConsumesComFreeSnapshot()
    {
        var snapshot = new FirewallRuleSnapshot(
            "Demo Rule",
            "[MFW-AutoAllow-Publisher:Contoso] hidden",
            true,
            1,
            true,
            6,
            @"C:\Apps\demo.exe",
            "DemoService",
            "443",
            "*",
            "10.0.0.1",
            "*",
            7,
            "Demo Group - MFW",
            "All",
            "");

        var viewModel = FirewallDataService.CreateAdvancedRuleViewModel(snapshot);

        Assert.Equal("Demo Rule", viewModel.Name);
        Assert.Equal(string.Empty, viewModel.Description);
        Assert.Equal("Contoso", viewModel.AutoAllowedPublisher);
        Assert.True(viewModel.IsEnabled);
        Assert.Equal("Allow", viewModel.Status);
        Assert.Equal(Directions.Incoming, viewModel.Direction);
        Assert.Equal("TCP", viewModel.ProtocolName);
        Assert.Equal(@"C:\Apps\demo.exe", viewModel.ApplicationName);
        Assert.Equal("DemoService", viewModel.ServiceName);
        Assert.Equal("All", viewModel.Profiles);
        Assert.Equal("All", viewModel.InterfaceTypes);
    }

    [Fact]
    public void ReenableMfwRules_RoutesToQueryBackend()
    {
        var query = new FakeQueryBackend();
        var service = CreateService(new RecordingLogger(), new RecordingLifecycleBackend(), query);

        service.ReenableMfwRules();

        Assert.Equal(1, query.EnableCalls);
    }

    [Fact]
    public void ReenableMfwRules_LogsPerRuleFailuresAndDoesNotThrow()
    {
        var logger = new RecordingLogger();
        var failure = new COMException("rule locked", unchecked((int)0x80070005));
        var query = new FakeQueryBackend
        {
            EnableResult = FirewallRuleQueryResult<int>.Success(
                1, [new FirewallRuleOperationFailure("Rule A", failure)])
        };
        var service = CreateService(logger, new RecordingLifecycleBackend(), query);

        service.ReenableMfwRules();

        var logged = Assert.Single(logger.Exceptions);
        Assert.Same(failure, logged.Exception);
        Assert.Contains("Rule A", logged.Context);
    }

    [Fact]
    public void ReenableMfwRules_BackendFailure_IsLoggedThroughLogException()
    {
        var logger = new RecordingLogger();
        var exception = new UnauthorizedAccessException("denied");
        var query = new FakeQueryBackend
        {
            EnableResult = FirewallRuleQueryResult<int>.Failure("enable failed", exception)
        };
        var service = CreateService(logger, new RecordingLifecycleBackend(), query);

        service.ReenableMfwRules();

        Assert.Same(exception, Assert.Single(logger.Exceptions).Exception);
    }

    [Fact]
    public void SetGroupEnabledState_RoutesGroupAndStateToQueryBackend()
    {
        var query = new FakeQueryBackend();
        var service = CreateService(new RecordingLogger(), new RecordingLifecycleBackend(), query);

        service.SetGroupEnabledState("Demo Group", false);

        Assert.Equal([("Demo Group", false)], query.GroupCalls);
    }

    [Fact]
    public void SetGroupEnabledState_PerRuleFailureIsLoggedAndOtherRulesAreNotAborted()
    {
        var logger = new RecordingLogger();
        var failure = new COMException("rule locked", unchecked((int)0x80070005));
        var query = new FakeQueryBackend
        {
            GroupResult = FirewallRuleQueryResult<int>.Success(
                2, [new FirewallRuleOperationFailure("Rule 3", failure)])
        };
        var service = CreateService(logger, new RecordingLifecycleBackend(), query);

        service.SetGroupEnabledState("Demo Group", true);

        var logged = Assert.Single(logger.Exceptions);
        Assert.Same(failure, logged.Exception);
        Assert.Contains("Rule 3", logged.Context);
    }

    [Fact]
    public void SetGroupEnabledState_BackendFailure_DoesNotThrowAndLogsException()
    {
        var logger = new RecordingLogger();
        var exception = new COMException("mpssvc stopped", unchecked((int)0x800706D9));
        var query = new FakeQueryBackend
        {
            GroupResult = FirewallRuleQueryResult<int>.Failure("group failed", exception)
        };
        var service = CreateService(logger, new RecordingLifecycleBackend(), query);

        service.SetGroupEnabledState("Demo Group", true);

        Assert.Same(exception, Assert.Single(logger.Exceptions).Exception);
    }

    [Fact]
    public async Task CleanUpOrphanedRulesAsync_DeletesOnlyRulesWhosePathIsMissing()
    {
        string existingPath = Assembly.GetExecutingAssembly().Location;
        var lifecycle = new RecordingLifecycleBackend();
        var query = new FakeQueryBackend
        {
            Rules =
            [
                Rule("Orphan", @"C:\__mfw_missing__\gone.exe"),
                Rule("Existing", existingPath),
                Rule("AnyApp", "*"),
                Rule("Uwp", "@{package}")
            ]
        };
        var service = CreateService(new RecordingLogger(), lifecycle, query);

        var orphaned = await service.CleanUpOrphanedRulesAsync(CancellationToken.None);

        Assert.Equal(["Orphan"], orphaned);
        Assert.Equal(["Orphan"], lifecycle.DeletedByName);
    }

    [Fact]
    public async Task CleanUpOrphanedRulesAsync_QueryFailure_ReturnsEmptyAndDeletesNothing()
    {
        var logger = new RecordingLogger();
        var lifecycle = new RecordingLifecycleBackend();
        var exception = new COMException("query failed", unchecked((int)0x80070005));
        var query = new FakeQueryBackend
        {
            QueryResult = FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Failure("query failed", exception)
        };
        var service = CreateService(logger, lifecycle, query);

        var orphaned = await service.CleanUpOrphanedRulesAsync(CancellationToken.None);

        Assert.Empty(orphaned);
        Assert.Empty(lifecycle.DeletedByName);
        Assert.Same(exception, Assert.Single(logger.Exceptions).Exception);
    }

    [Fact]
    public void FindAndQueueDelete_DeletesOnlyMatchingGeneralBlockRules()
    {
        var lifecycle = new RecordingLifecycleBackend();
        var query = new FakeQueryBackend
        {
            Rules =
            [
                Rule("GeneralBlock", AppPath, protocol: 256, isBlock: true, local: "*", remote: "*"),
                Rule("AllowRule", AppPath, protocol: 256, isBlock: false, local: "*", remote: "*"),
                Rule("TcpBlock", AppPath, protocol: 6, isBlock: true, local: "*", remote: "*"),
                Rule("PortBlock", AppPath, protocol: 256, isBlock: true, local: "443", remote: "*"),
                Rule("RemotePortBlock", AppPath, protocol: 256, isBlock: true, local: "*", remote: "80"),
                Rule("OtherApp", @"C:\Apps\other.exe", protocol: 256, isBlock: true, local: "*", remote: "*")
            ]
        };
        var service = CreateService(new RecordingLogger(), lifecycle, query);

        InvokeFindAndQueueDelete(service, AppPath);

        Assert.Equal(1, query.QueryCalls);
        Assert.Equal(["GeneralBlock"], lifecycle.DeletedByName);
    }

    [Fact]
    public void FindAndQueueDelete_QueryFailure_LogsExceptionAndDeletesNothing()
    {
        var logger = new RecordingLogger();
        var lifecycle = new RecordingLifecycleBackend();
        var exception = new UnauthorizedAccessException("denied");
        var query = new FakeQueryBackend
        {
            QueryResult = FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Failure("query failed", exception)
        };
        var service = CreateService(logger, lifecycle, query);

        InvokeFindAndQueueDelete(service, AppPath);

        Assert.Empty(lifecycle.DeletedByName);
        Assert.Same(exception, Assert.Single(logger.Exceptions).Exception);
    }

    [Fact]
    public void FindAndQueueDelete_DeleteFailure_IsLoggedThroughLogException()
    {
        var logger = new RecordingLogger();
        var exception = new COMException("delete failed", unchecked((int)0x80070005));
        var lifecycle = new RecordingLifecycleBackend
        {
            Result = FirewallRuleLifecycleOperationResult.Failure("delete rules by name failed", exception)
        };
        var query = new FakeQueryBackend
        {
            Rules = [Rule("GeneralBlock", AppPath, protocol: 256, isBlock: true, local: "*", remote: "*")]
        };
        var service = CreateService(logger, lifecycle, query);

        InvokeFindAndQueueDelete(service, AppPath);

        Assert.Equal(["GeneralBlock"], lifecycle.DeletedByName);
        Assert.Same(exception, Assert.Single(logger.Exceptions).Exception);
    }

    private static FirewallRuleSummary Rule(
        string name,
        string applicationName,
        int protocol = 256,
        bool isBlock = false,
        string local = "*",
        string remote = "*")
        => new(name, applicationName, "Minimal Firewall - MFW", protocol, isBlock, local, remote);

    private static void InvokeFindAndQueueDelete(FirewallActionsService service, string appPath)
    {
        var method = typeof(FirewallActionsService).GetMethod(
            "FindAndQueueDeleteForGeneralBlockRule",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("FindAndQueueDeleteForGeneralBlockRule was not found.");

        method.Invoke(service, [appPath]);
    }

    private static FirewallActionsService CreateService(
        UserActivityLogger logger,
        IFirewallRuleLifecycleBackend lifecycle,
        IFirewallRuleQueryBackend query)
        => new(
            null!,
            logger,
            null!,
            null!,
            null!,
            null!,
            null!,
            null,
            null,
            lifecycle,
            query);

    private sealed class RecordingLogger : UserActivityLogger
    {
        public List<(string Context, Exception Exception)> Exceptions { get; } = [];
        public List<string> DebugMessages { get; } = [];

        public override void LogException(string context, Exception ex) => Exceptions.Add((context, ex));

        public override void LogDebug(string message) => DebugMessages.Add(message);
    }

    private sealed class FakeQueryBackend : IFirewallRuleQueryBackend
    {
        public List<FirewallRuleSummary> Rules { get; init; } = [];
        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>? QueryResult { get; init; }
        public FirewallRuleQueryResult<int> EnableResult { get; init; } = FirewallRuleQueryResult<int>.Success(0);
        public FirewallRuleQueryResult<int> GroupResult { get; init; } = FirewallRuleQueryResult<int>.Success(0);
        public int QueryCalls { get; private set; }
        public int EnableCalls { get; private set; }
        public List<(string Group, bool Enabled)> GroupCalls { get; } = [];

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>> GetAllRuleSnapshots()
            => FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSnapshot>>.Success([]);

        public FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>> GetMfwRules()
        {
            QueryCalls++;
            return QueryResult
                ?? FirewallRuleQueryResult<IReadOnlyList<FirewallRuleSummary>>.Success(Rules);
        }

        public FirewallRuleQueryResult<int> EnableMfwRules()
        {
            EnableCalls++;
            return EnableResult;
        }

        public FirewallRuleQueryResult<int> SetGroupEnabled(string groupName, bool isEnabled)
        {
            GroupCalls.Add((groupName, isEnabled));
            return GroupResult;
        }
    }

    private sealed class RecordingLifecycleBackend : IFirewallRuleLifecycleBackend
    {
        public List<string> DeletedByName { get; } = [];
        public FirewallRuleLifecycleOperationResult Result { get; init; } = FirewallRuleLifecycleOperationResult.Success();

        public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames)
        {
            DeletedByName.AddRange(ruleNames);
            return Result;
        }

        public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths) => Result;
        public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames) => Result;
        public FirewallRuleLifecycleOperationResult DeleteByDescription(string description) => Result;
        public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName) => Result;
        public FirewallRuleLifecycleOperationResult DeleteAllMfwRules() => Result;
        public FirewallRuleLifecycleOperationResult EnableByName(string ruleName) => Result;
        public FirewallRuleLifecycleOperationResult DisableByName(string ruleName) => Result;
    }
}
