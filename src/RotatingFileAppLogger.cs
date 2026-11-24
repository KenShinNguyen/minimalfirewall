using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace MinimalFirewall;

public sealed class RotatingFileAppLogger : IAppLogger
{
    public const long DefaultMaxFileBytes = 5L * 1024 * 1024;
    public const int DefaultMaxTotalFiles = 3;
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);
    private readonly Lock _syncLock = new();
    private readonly string _logFilePath;
    private readonly long _maxFileBytes;
    private readonly int _maxTotalFiles;
    private readonly TimeProvider _timeProvider;
    public AppLogLevel MinimumLevel { get; set; }

    public RotatingFileAppLogger(string logFilePath, AppLogLevel minimumLevel = AppLogLevel.Info, long maxFileBytes = DefaultMaxFileBytes, int maxTotalFiles = DefaultMaxTotalFiles, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logFilePath);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFileBytes, 128);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxTotalFiles, 1);
        _logFilePath = logFilePath; MinimumLevel = minimumLevel; _maxFileBytes = maxFileBytes; _maxTotalFiles = maxTotalFiles; _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public void Debug(string category, string message) => Log(AppLogLevel.Debug, category, message);
    public void Info(string category, string message) => Log(AppLogLevel.Info, category, message);
    public void Warning(string category, string message, Exception? exception = null) => Log(AppLogLevel.Warning, category, message, exception);
    public void Error(string category, string message, Exception? exception = null, string? errorId = null) => Log(AppLogLevel.Error, category, message, exception, errorId);

    public void Log(AppLogLevel level, string category, string message, Exception? exception = null, string? errorId = null)
    {
        if (level < MinimumLevel) return;
        string line = FormatEntry(level, category, message, exception, errorId);
        byte[] payload = Utf8NoBom.GetBytes(line);
        try
        {
            using (_syncLock.EnterScope())
            {
                EnsureDirectoryExists(); RotateIfNeeded(payload.Length);
                using var stream = new FileStream(_logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                stream.Write(payload, 0, payload.Length); stream.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Debug.WriteLine($"[LoggerFallback] Failed to write log: {ex.Message}");
        }
    }

    private string FormatEntry(AppLogLevel level, string category, string message, Exception? exception, string? errorId)
    {
        string timestamp = _timeProvider.GetUtcNow().ToString("O", CultureInfo.InvariantCulture);
        string safeCategory = string.IsNullOrWhiteSpace(category) ? "General" : category.Trim();
        string levelTag = level switch { AppLogLevel.Debug => "DBG", AppLogLevel.Info => "INF", AppLogLevel.Warning => "WRN", AppLogLevel.Error => "ERR", _ => "INF" };
        var builder = new StringBuilder(256);
        builder.Append(timestamp).Append(" [").Append(levelTag).Append("] [").Append(safeCategory).Append(']');
        if (!string.IsNullOrWhiteSpace(errorId)) builder.Append(" [").Append(errorId.Trim()).Append(']');
        builder.Append(' ').AppendLine(message ?? string.Empty);
        if (exception is not null) builder.Append("  Exception: ").AppendLine(exception.ToString());
        return builder.ToString();
    }

    private void EnsureDirectoryExists()
    {
        string? directory = Path.GetDirectoryName(_logFilePath);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
    }

    private void RotateIfNeeded(int incomingByteCount)
    {
        var current = new FileInfo(_logFilePath);
        if (!current.Exists || current.Length + incomingByteCount <= _maxFileBytes) return;
        if (_maxTotalFiles == 1) { File.Delete(_logFilePath); return; }
        for (int index = _maxTotalFiles - 2; index >= 1; index--)
        {
            string source = $"{_logFilePath}.{index}"; string destination = $"{_logFilePath}.{index + 1}";
            if (File.Exists(source)) File.Move(source, destination, overwrite: true);
        }
        File.Move(_logFilePath, $"{_logFilePath}.1", overwrite: true);
    }
}
