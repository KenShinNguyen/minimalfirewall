using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class SafeAsyncRunnerTests
{
    [Fact]
    public async Task RunUi_WhenOperationThrows_LogsErrorWithErrorIdAndInvokesOnError()
    {
        var logger = new TestAppLogger();
        var completion = new TaskCompletionSource<(string Id, Exception Error)>(TaskCreationOptions.RunContinuationsAsynchronously);

        SafeAsyncRunner.RunUi(
            () => Task.FromException(new InvalidOperationException("boom")),
            logger,
            "Test",
            "Operation",
            (id, ex) => completion.TrySetResult((id, ex)));

        var result = await completion.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.StartsWith("ERR-", result.Id);
        Assert.Equal("boom", result.Error.Message);
        var entry = Assert.Single(logger.Errors);
        Assert.Equal(result.Id, entry.ErrorId);
    }

    [Fact]
    public async Task RunUi_WhenOperationCancelled_LogsDebugAndDoesNotInvokeOnError()
    {
        var logger = new TestAppLogger();
        bool called = false;
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        SafeAsyncRunner.RunUi(
            async () => { await Task.Yield(); throw new OperationCanceledException(); },
            logger,
            "Test",
            "Operation",
            (_, _) => called = true);

        await Task.Delay(50);
        completed.TrySetResult();
        await completed.Task;
        Assert.False(called);
        Assert.Contains(logger.DebugMessages, message => message.Contains("cancelled", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunBackground_WhenPreviousExecutionInFlight_SkipsOverlappingCallAndResetsFlagAfterCompletion()
    {
        var logger = new TestAppLogger();
        int inFlight = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int executions = 0;

        SafeAsyncRunner.RunBackground(
            async () => { Interlocked.Increment(ref executions); await release.Task; },
            logger, "Test", "Background", ref inFlight);

        await Task.Delay(50);
        SafeAsyncRunner.RunBackground(
            () => { Interlocked.Increment(ref executions); return Task.CompletedTask; },
            logger, "Test", "Background", ref inFlight);

        Assert.Equal(1, executions);
        release.TrySetResult();
        await Task.Delay(50);
        Assert.Equal(0, Volatile.Read(ref inFlight));

        SafeAsyncRunner.RunBackground(
            () => { Interlocked.Increment(ref executions); return Task.CompletedTask; },
            logger, "Test", "Background", ref inFlight);

        await Task.Delay(50);
        Assert.Equal(2, executions);
    }

    private sealed class TestAppLogger : IAppLogger
    {
        public AppLogLevel MinimumLevel { get; set; } = AppLogLevel.Debug;
        public List<string> DebugMessages { get; } = [];
        public List<(string ErrorId, Exception Exception)> Errors { get; } = [];

        public void Log(AppLogLevel level, string category, string message, Exception? exception = null, string? errorId = null)
        {
            if (level == AppLogLevel.Debug) DebugMessages.Add(message);
            if (level == AppLogLevel.Error && exception is not null) Errors.Add((errorId ?? string.Empty, exception));
        }
    }
}
