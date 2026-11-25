using System;
using System.Collections.Concurrent;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class EventListenerFailureDiagnosticsTests
{
    [Fact]
    public void StartupFailure_IsLoggedAsErrorEvenWhenOptionalActivityLoggingIsDisabled()
    {
        var logger = new RecordingAppLogger();
        var activityLogger = new UserActivityLogger(logger)
        {
            IsEnabled = false
        };

        // Mirror the application path: durable app log is written separately from
        // the optional activity/debug log which may legitimately be disabled.
        EventListenerFailureDiagnostics.LogStartupFailure(
            logger,
            "Could not read the Windows Security event log.");

        activityLogger.LogDebug(
            "Event listener startup failed: Could not read the Windows Security event log.");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(AppLogLevel.Error, entry.Level);
        Assert.Equal(nameof(FirewallEventListenerService), entry.Category);
        Assert.Contains("Windows Security event log", entry.Message, StringComparison.Ordinal);
        Assert.StartsWith("ERR-", entry.ErrorId);
        Assert.Null(entry.Exception);
    }

    [Fact]
    public void StartupFailure_RejectsBlankDiagnosticMessage()
    {
        var logger = new RecordingAppLogger();

        Assert.Throws<ArgumentException>(
            () => EventListenerFailureDiagnostics.LogStartupFailure(logger, " "));
        Assert.Empty(logger.Entries);
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
