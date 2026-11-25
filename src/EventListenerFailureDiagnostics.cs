namespace MinimalFirewall;

/// <summary>
/// Records event-listener startup failures independently from optional user activity logging.
/// Failure to read the Windows Security log is operationally significant because blocked
/// connection telemetry becomes unavailable.
/// </summary>
internal static class EventListenerFailureDiagnostics
{
    internal static void LogStartupFailure(IAppLogger logger, string message)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        logger.Error(
            nameof(FirewallEventListenerService),
            $"Startup failed: {message}",
            errorId: SafeAsyncRunner.CreateErrorId());
    }
}
