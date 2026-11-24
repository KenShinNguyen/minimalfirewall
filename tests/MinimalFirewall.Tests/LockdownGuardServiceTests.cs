using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class LockdownGuardServiceTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset BaseUtc = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Constructor_WhenRequiredDependenciesAreNull_ThrowsArgumentNullException()
    {
        var backend = new FakeLockdownBackend();
        var logger = new InMemoryAppLogger();

        Assert.Throws<ArgumentNullException>(() => new LockdownGuardService(null!, logger));
        Assert.Throws<ArgumentNullException>(() => new LockdownGuardService(backend, null!));
    }

    [Fact]
    public async Task EvaluateOnce_WhenDesiredInactive_ReturnsInactiveWithoutQueryingBackend()
    {
        var backend = new FakeLockdownBackend();
        await using var guard = new LockdownGuardService(backend, new InMemoryAppLogger(), new FixedTimeProvider(BaseUtc));

        Assert.Equal(LockdownEnforcementOutcome.Inactive, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(0, backend.GetSnapshotCalls);
        Assert.Equal(0, backend.ApplyLockdownCalls);
    }

    [Fact]
    public async Task EvaluateOnce_WhenFullyLockedDown_ReturnsCompliantWithoutApplyingOrRaisingEvent()
    {
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(false, true) };
        var raised = new List<LockdownGuardEventArgs>();
        await using var guard = new LockdownGuardService(backend, new InMemoryAppLogger(), new FixedTimeProvider(BaseUtc));
        guard.EnforcementEvaluated += (_, args) => raised.Add(args);

        await guard.SetDesiredLockdownAsync(true);
        Assert.Equal(LockdownEnforcementOutcome.Compliant, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(1, backend.GetSnapshotCalls);
        Assert.Equal(0, backend.ApplyLockdownCalls);
        Assert.Empty(raised);
    }

    [Fact]
    public async Task EvaluateOnce_WhenDriftDetected_RestoresAndRaisesEvent()
    {
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(false, false) };
        var logger = new InMemoryAppLogger();
        var raised = new List<LockdownGuardEventArgs>();
        var clock = new FixedTimeProvider(BaseUtc);
        await using var guard = new LockdownGuardService(backend, logger, clock);
        guard.EnforcementEvaluated += (_, args) => raised.Add(args);

        await guard.SetDesiredLockdownAsync(true);
        clock.Advance(TimeSpan.FromSeconds(10));

        Assert.Equal(LockdownEnforcementOutcome.Restored, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(1, backend.ApplyLockdownCalls);
        var evt = Assert.Single(raised);
        Assert.Equal(LockdownEnforcementOutcome.Restored, evt.Outcome);
        Assert.Equal(BaseUtc.AddSeconds(10), evt.ObservedAtUtc);
        Assert.Contains(logger.Entries, e => e.Level == AppLogLevel.Warning && e.Message.Contains("drift", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task EvaluateOnce_WhenRestoreFails_ReturnsRestoreFailedAndRaisesEvent()
    {
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(false, false), ApplyLockdownResult = false };
        var raised = new List<LockdownGuardEventArgs>();
        await using var guard = new LockdownGuardService(backend, new InMemoryAppLogger(), new FixedTimeProvider(BaseUtc));
        guard.EnforcementEvaluated += (_, args) => raised.Add(args);

        await guard.SetDesiredLockdownAsync(true);

        Assert.Equal(LockdownEnforcementOutcome.RestoreFailed, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(1, backend.ApplyLockdownCalls);
        Assert.Equal(LockdownEnforcementOutcome.RestoreFailed, Assert.Single(raised).Outcome);
    }

    [Fact]
    public async Task EvaluateOnce_WhenPolicyStateIsUnknown_SkipsOverwrite()
    {
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(true, false) };
        var logger = new InMemoryAppLogger();
        var raised = new List<LockdownGuardEventArgs>();
        await using var guard = new LockdownGuardService(backend, logger, new FixedTimeProvider(BaseUtc));
        guard.EnforcementEvaluated += (_, args) => raised.Add(args);

        await guard.SetDesiredLockdownAsync(true);

        Assert.Equal(LockdownEnforcementOutcome.SkippedUnknownState, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(0, backend.ApplyLockdownCalls);
        var evt = Assert.Single(raised);
        Assert.Equal(BaseUtc, evt.ObservedAtUtc);
        Assert.Contains(logger.Entries, e => e.Level == AppLogLevel.Warning && e.Message.Contains("Unknown", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task EvaluateOnce_WhenBackendThrowsException_ReturnsRestoreFailedWithoutApplying()
    {
        var backend = new FakeLockdownBackend { ExceptionToThrowOnGetSnapshot = new InvalidOperationException("Simulated MpsSvc failure") };
        var logger = new InMemoryAppLogger();
        var raised = new List<LockdownGuardEventArgs>();
        await using var guard = new LockdownGuardService(backend, logger, new FixedTimeProvider(BaseUtc));
        guard.EnforcementEvaluated += (_, args) => raised.Add(args);

        await guard.SetDesiredLockdownAsync(true);

        Assert.Equal(LockdownEnforcementOutcome.RestoreFailed, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(0, backend.ApplyLockdownCalls);
        Assert.Contains(logger.Entries, e => e.Level == AppLogLevel.Error && e.Exception is InvalidOperationException);
        Assert.Contains("MpsSvc", Assert.Single(raised).Details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetDesiredLockdownFalse_PreventsSubsequentEvaluationFromReEnabling()
    {
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(false, false) };
        await using var guard = new LockdownGuardService(backend, new InMemoryAppLogger(), new FixedTimeProvider(BaseUtc));

        await guard.SetDesiredLockdownAsync(true);
        Assert.Equal(LockdownEnforcementOutcome.Restored, await guard.EvaluateAndEnforceOnceAsync());

        await guard.SetDesiredLockdownAsync(false);
        Assert.Equal(LockdownEnforcementOutcome.Inactive, await guard.EvaluateAndEnforceOnceAsync());
        Assert.Equal(1, backend.ApplyLockdownCalls);
    }

    [Fact]
    public async Task SetDesiredLockdownAsync_WhileEvaluationInFlight_SerializesThroughGate()
    {
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);

        var backend = new FakeLockdownBackend
        {
            CurrentSnapshot = new(false, true),
            OnGetSnapshot = () =>
            {
                entered.Set();
                Assert.True(release.Wait(TestTimeout), "Timed out waiting to release snapshot.");
            }
        };

        await using var guard = new LockdownGuardService(backend, new InMemoryAppLogger(), new FixedTimeProvider(BaseUtc));
        await guard.SetDesiredLockdownAsync(true);

        Task<LockdownEnforcementOutcome> evalTask = Task.Run(() => guard.EvaluateAndEnforceOnceAsync());
        Assert.True(entered.Wait(TestTimeout), "Evaluation did not enter backend snapshot.");

        Task disableTask = guard.SetDesiredLockdownAsync(false);
        Assert.False(disableTask.IsCompleted);

        release.Set();
        Assert.Equal(LockdownEnforcementOutcome.Compliant, await evalTask.WaitAsync(TestTimeout));
        await disableTask.WaitAsync(TestTimeout);
        Assert.Equal(LockdownEnforcementOutcome.Inactive, await guard.EvaluateAndEnforceOnceAsync());
    }

    [Fact]
    public async Task Start_WhenDriftDetectedOnPeriodicTick_RestoresAndDisposesCleanly()
    {
        var restored = new TaskCompletionSource<LockdownGuardEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
        var backend = new FakeLockdownBackend { CurrentSnapshot = new(false, false) };
        var clock = new FixedTimeProvider(BaseUtc);
        await using var guard = new LockdownGuardService(
            backend,
            new InMemoryAppLogger(),
            clock,
            TimeSpan.FromMilliseconds(15));

        guard.EnforcementEvaluated += (_, args) =>
        {
            if (args.Outcome == LockdownEnforcementOutcome.Restored)
            {
                backend.CurrentSnapshot = new(false, true);
                restored.TrySetResult(args);
            }
        };

        await guard.SetDesiredLockdownAsync(true);
        guard.Start();

        var evt = await restored.Task.WaitAsync(TestTimeout);
        Assert.Equal(LockdownEnforcementOutcome.Restored, evt.Outcome);
        Assert.True(backend.ApplyLockdownCalls >= 1);
    }

    private sealed class FakeLockdownBackend : ILockdownPolicyBackend
    {
        public LockdownPolicySnapshot CurrentSnapshot { get; set; } = new(false, true);
        public bool ApplyLockdownResult { get; set; } = true;
        public Exception? ExceptionToThrowOnGetSnapshot { get; set; }
        public Action? OnGetSnapshot { get; set; }
        public int GetSnapshotCalls { get; private set; }
        public int ApplyLockdownCalls { get; private set; }

        public LockdownPolicySnapshot GetLockdownPolicySnapshot()
        {
            GetSnapshotCalls++;
            OnGetSnapshot?.Invoke();
            if (ExceptionToThrowOnGetSnapshot is not null) throw ExceptionToThrowOnGetSnapshot;
            return CurrentSnapshot;
        }

        public bool ApplyLockdownPolicy()
        {
            ApplyLockdownCalls++;
            return ApplyLockdownResult;
        }
    }

    private sealed class InMemoryAppLogger : IAppLogger
    {
        public AppLogLevel MinimumLevel { get; set; } = AppLogLevel.Debug;
        public List<CapturedLogEntry> Entries { get; } = [];

        public void Log(AppLogLevel level, string category, string message, Exception? exception = null, string? errorId = null)
            => Entries.Add(new CapturedLogEntry(level, category, message, exception, errorId));
    }

    private sealed record CapturedLogEntry(
        AppLogLevel Level,
        string Category,
        string Message,
        Exception? Exception,
        string? ErrorId);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan value) => _utcNow += value;
    }
}
