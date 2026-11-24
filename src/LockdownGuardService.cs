using System;
using System.Threading;
using System.Threading.Tasks;

namespace MinimalFirewall;

public interface ILockdownPolicyBackend
{
    LockdownPolicySnapshot GetLockdownPolicySnapshot();
    bool ApplyLockdownPolicy();
}

public readonly record struct LockdownPolicySnapshot(bool IsUnknown, bool IsFullyLockedDown);

public enum LockdownEnforcementOutcome
{
    Inactive,
    Compliant,
    Restored,
    RestoreFailed,
    SkippedUnknownState
}

public sealed class LockdownGuardEventArgs : EventArgs
{
    public LockdownGuardEventArgs(
        LockdownEnforcementOutcome outcome,
        DateTimeOffset observedAtUtc,
        string details)
    {
        Outcome = outcome;
        ObservedAtUtc = observedAtUtc;
        Details = details;
    }

    public LockdownEnforcementOutcome Outcome { get; }
    public DateTimeOffset ObservedAtUtc { get; }
    public string Details { get; }
}

public sealed class LockdownGuardService : IAsyncDisposable
{
    private readonly ILockdownPolicyBackend _backend;
    private readonly IAppLogger _logger;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _pollInterval;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _lifecycleLock = new();

    private CancellationTokenSource? _stopCts;
    private PeriodicTimer? _timer;
    private Task? _loopTask;
    private bool _desiredLockdown;
    private bool _disposed;

    public LockdownGuardService(
        ILockdownPolicyBackend backend,
        IAppLogger logger,
        TimeProvider? timeProvider = null,
        TimeSpan? pollInterval = null)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(30);

        if (_pollInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }
    }

    public event EventHandler<LockdownGuardEventArgs>? EnforcementEvaluated;

    public async Task SetDesiredLockdownAsync(bool desiredLockdown)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _desiredLockdown = desiredLockdown;
            _logger.Info(
                nameof(LockdownGuardService),
                desiredLockdown ? "Lockdown guard enabled." : "Lockdown guard disabled.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<LockdownEnforcementOutcome> EvaluateAndEnforceOnceAsync()
    {
        ThrowIfDisposed();
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_desiredLockdown)
            {
                return LockdownEnforcementOutcome.Inactive;
            }

            DateTimeOffset observedAtUtc = _timeProvider.GetUtcNow();

            LockdownPolicySnapshot snapshot;
            try
            {
                snapshot = _backend.GetLockdownPolicySnapshot();
            }
            catch (Exception ex)
            {
                _logger.Error(
                    nameof(LockdownGuardService),
                    "Failed to read Lockdown policy state.",
                    ex,
                    SafeAsyncRunner.CreateErrorId());

                var failed = new LockdownGuardEventArgs(
                    LockdownEnforcementOutcome.RestoreFailed,
                    observedAtUtc,
                    $"Lockdown policy read failed: {ex.Message}");
                EnforcementEvaluated?.Invoke(this, failed);
                return LockdownEnforcementOutcome.RestoreFailed;
            }

            if (snapshot.IsUnknown)
            {
                _logger.Warning(
                    nameof(LockdownGuardService),
                    "Lockdown policy state is Unknown; refusing to overwrite it.");

                var skipped = new LockdownGuardEventArgs(
                    LockdownEnforcementOutcome.SkippedUnknownState,
                    observedAtUtc,
                    "Lockdown policy state is Unknown; enforcement was skipped.");
                EnforcementEvaluated?.Invoke(this, skipped);
                return LockdownEnforcementOutcome.SkippedUnknownState;
            }

            if (snapshot.IsFullyLockedDown)
            {
                return LockdownEnforcementOutcome.Compliant;
            }

            bool restored;
            try
            {
                restored = _backend.ApplyLockdownPolicy();
            }
            catch (Exception ex)
            {
                _logger.Error(
                    nameof(LockdownGuardService),
                    "Failed to restore Lockdown policy.",
                    ex,
                    SafeAsyncRunner.CreateErrorId());
                restored = false;
            }

            LockdownEnforcementOutcome outcome = restored
                ? LockdownEnforcementOutcome.Restored
                : LockdownEnforcementOutcome.RestoreFailed;

            if (restored)
            {
                _logger.Warning(
                    nameof(LockdownGuardService),
                    "Lockdown policy drift detected and restored.");
            }
            else
            {
                _logger.Error(
                    nameof(LockdownGuardService),
                    "Lockdown policy drift detected but restoration failed.");
            }

            EnforcementEvaluated?.Invoke(
                this,
                new LockdownGuardEventArgs(
                    outcome,
                    observedAtUtc,
                    restored
                        ? "Lockdown policy was restored."
                        : "Lockdown policy restoration failed."));

            return outcome;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Start()
    {
        ThrowIfDisposed();

        lock (_lifecycleLock)
        {
            if (_loopTask is not null)
            {
                return;
            }

            _stopCts = new CancellationTokenSource();
            _timer = new PeriodicTimer(_pollInterval, _timeProvider);
            _loopTask = RunLoopAsync(_timer, _stopCts.Token);
        }
    }

    private async Task RunLoopAsync(PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                await EvaluateAndEnforceOnceAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed))
        {
        }
        catch (Exception ex)
        {
            _logger.Error(
                nameof(LockdownGuardService),
                "Lockdown guard loop terminated unexpectedly.",
                ex,
                SafeAsyncRunner.CreateErrorId());
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task? loopTask;
        lock (_lifecycleLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _stopCts?.Cancel();
            _timer?.Dispose();
            loopTask = _loopTask;
        }

        if (loopTask is not null)
        {
            await loopTask.ConfigureAwait(false);
        }

        _stopCts?.Dispose();
        _gate.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LockdownGuardService));
        }
    }
}
