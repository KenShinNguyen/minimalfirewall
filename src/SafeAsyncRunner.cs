using System;
using System.Threading;
using System.Threading.Tasks;

namespace MinimalFirewall;

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

    public static async void RunBackground(Func<Task> operation, IAppLogger logger, string category, string operationName, ref int inFlightFlag)
    {
        if (Interlocked.Exchange(ref inFlightFlag, 1) == 1)
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
            Volatile.Write(ref inFlightFlag, 0);
        }
    }
}
