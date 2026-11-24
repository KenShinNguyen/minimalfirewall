using System;

namespace MinimalFirewall;

public enum AppLogLevel { Debug = 0, Info = 1, Warning = 2, Error = 3 }

public interface IAppLogger
{
    AppLogLevel MinimumLevel { get; set; }
    void Log(AppLogLevel level, string category, string message, Exception? exception = null, string? errorId = null);
    void Debug(string category, string message) => Log(AppLogLevel.Debug, category, message);
    void Info(string category, string message) => Log(AppLogLevel.Info, category, message);
    void Warning(string category, string message, Exception? exception = null) => Log(AppLogLevel.Warning, category, message, exception);
    void Error(string category, string message, Exception? exception = null, string? errorId = null) => Log(AppLogLevel.Error, category, message, exception, errorId);
}

public sealed class NullAppLogger : IAppLogger
{
    public static NullAppLogger Instance { get; } = new();
    public AppLogLevel MinimumLevel { get; set; } = AppLogLevel.Error;
    private NullAppLogger() { }
    public void Log(AppLogLevel level, string category, string message, Exception? exception = null, string? errorId = null) { }
}

public static class AppLog
{
    private static IAppLogger _current = NullAppLogger.Instance;
    public static IAppLogger Current => _current;
    public static void Initialize(IAppLogger logger) { ArgumentNullException.ThrowIfNull(logger); _current = logger; }
}
