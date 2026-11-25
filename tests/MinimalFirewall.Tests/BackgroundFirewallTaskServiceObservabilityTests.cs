using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading.Tasks;
using MinimalFirewall.Tests.Fakes;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class BackgroundFirewallTaskServiceObservabilityTests
{
    [Fact]
    public async Task EventSubscriberFailures_AreLoggedAndDoNotStopQueueWorker()
    {
        using var scope = new TaskServiceScope();
        using var service = scope.CreateService();
        var queueFailure = new InvalidOperationException("queue subscriber failed");
        var statusFailure = new InvalidOperationException("status subscriber failed");

        service.QueueCountChanged += _ => throw queueFailure;
        service.StatusChanged += _ => throw statusFailure;

        service.EnqueueTask(new FirewallTask(
            (FirewallTaskType)int.MaxValue,
            new object(),
            "observability-test"));

        await service.WhenIdleAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(
            scope.Logger.Entries,
            entry => entry.Level == AppLogLevel.Error
                && entry.Category == nameof(BackgroundFirewallTaskService)
                && entry.Message.Contains(nameof(BackgroundFirewallTaskService.QueueCountChanged), StringComparison.Ordinal)
                && ReferenceEquals(entry.Exception, queueFailure));

        Assert.Contains(
            scope.Logger.Entries,
            entry => entry.Level == AppLogLevel.Error
                && entry.Category == nameof(BackgroundFirewallTaskService)
                && entry.Message.Contains(nameof(BackgroundFirewallTaskService.StatusChanged), StringComparison.Ordinal)
                && ReferenceEquals(entry.Exception, statusFailure));
    }

    private sealed class TaskServiceScope : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-task-service-observability-{Guid.NewGuid():N}");

        private readonly WildcardRuleService _wildcardRules;
        private readonly InMemoryFirewallBackend _backend = new();

        public RecordingAppLogger Logger { get; } = new();

        public TaskServiceScope()
        {
            Directory.CreateDirectory(_directory);
            _wildcardRules = new WildcardRuleService(
                Path.Combine(_directory, "wildcard_rules.json"));
        }

        public BackgroundFirewallTaskService CreateService()
        {
            var dataService = new FirewallDataService(
                _wildcardRules,
                new UwpService(Path.Combine(_directory, "uwp_apps.json")),
                new RuleTimestampService(Path.Combine(_directory, "timestamps.json")),
                _backend);

            var actionsService = new FirewallActionsService(
                new UserActivityLogger(),
                null!,
                null!,
                null!,
                _wildcardRules,
                dataService,
                _backend,
                _backend,
                _backend,
                _backend,
                _backend);

            return new BackgroundFirewallTaskService(
                actionsService,
                new UserActivityLogger(),
                _wildcardRules,
                dataService,
                Logger);
        }

        public void Dispose()
        {
            _wildcardRules.Dispose();
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }

    private sealed class RecordingAppLogger : IAppLogger
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();

        public AppLogLevel MinimumLevel { get; set; } = AppLogLevel.Debug;
        public LogEntry[] Entries => _entries.ToArray();

        public void Log(
            AppLogLevel level,
            string category,
            string message,
            Exception? exception = null,
            string? errorId = null)
            => _entries.Enqueue(new LogEntry(level, category, message, exception, errorId));
    }

    private sealed record LogEntry(
        AppLogLevel Level,
        string Category,
        string Message,
        Exception? Exception,
        string? ErrorId);
}
