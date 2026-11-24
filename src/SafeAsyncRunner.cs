using System;
using System.Threading;
using System.Threading.Tasks;

namespace MinimalFirewall;

public sealed class AsyncRunGate
{
    private int _inFlight;

    public bool TryEnter() => Interlocked.Exchange(ref _inFlight, 1) == 0;

    public void Exit() => Volatile.Write(ref _inFlight, 0);

    public bool IsInFlight => Volatile.Read(ref _inFlight) == 1;
}

public static class SafeAsyncRunner
{
    public static string CreateErrorId() => $"ERR-{Guid.NewGuid().ToString("N")[..8].ToUpperInvariant()}";

    public static async void RunUi(Func<Task> operation, IAppLogger logger, string category, string operationName, Action<string, Exception>? onError = null)
    {
        try
        {
            await operation();
        }
        catch (OperationCanceledException)
        {
            logger.Debug(category, $"{operationName} cancelled.");
        }
        catch (ObjectDisposedException)
        {
            logger.Debug(category, $"{operationName} skipped because control/form was disposed.");
        }
        catch (Exception ex)
        {
            string errorId = CreateErrorId();
            logger.Error(category, $"{operationName} failed.", ex, errorId);
            onError?.Invoke(errorId, ex);
        }
    }

    public static async void RunBackground(Func<Task> operation, IAppLogger logger, string category, string operationName, AsyncRunGate gate)
    {
        ArgumentNullException.ThrowIfNull(gate);

        if (!gate.TryEnter())
        {
            logger.Debug(category, $"{operationName} skipped because a previous execution is still running.");
            return;
        }

        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            logger.Debug(category, $"{operationName} cancelled.");
        }
        catch (Exception ex)
        {
            string errorId = CreateErrorId();
            logger.Error(category, $"{operationName} failed in background.", ex, errorId);
        }
        finally
        {
            gate.Exit();
        }
    }
}
