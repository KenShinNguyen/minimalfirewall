using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class RotatingFileAppLoggerTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "MinimalFirewallTests",
        Guid.NewGuid().ToString("N"));

    public RotatingFileAppLoggerTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void Log_WhenExceedingMaxFileBytes_RotatesAndKeepsAtMostThreeFiles()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug, 256, 3);

        for (int i = 0; i < 10; i++)
        {
            logger.Info("Test", new string((char)('A' + i), 220));
        }

        string[] files = Directory.GetFiles(_directory, "test.log*");
        Assert.True(files.Length <= 3);
        Assert.DoesNotContain(files, file => file.EndsWith(".3", StringComparison.Ordinal));
        Assert.Contains("J", File.ReadAllText(path));
    }

    [Fact]
    public void Log_WhenBelowMinimumLevel_DoesNotCreateOrWriteFile()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Info, 256);

        logger.Debug("Test", "debug");

        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Log_WithErrorIdAndException_FormatsStructuredLineAndPreservesHResult()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug);
        var exception = new InvalidOperationException("boom");

        logger.Error("Test", "failure", exception, "ERR-12345678");

        string text = File.ReadAllText(path);
        Assert.Contains("[ERR]", text);
        Assert.Contains("[Test]", text);
        Assert.Contains("[ERR-12345678]", text);
        Assert.Contains("failure", text);
        Assert.Contains("InvalidOperationException", text);
        Assert.Contains($"0x{exception.HResult:X8}", text);
    }

    [Fact]
    public void Log_WhenFieldsContainNewlines_EscapesTheyInsteadOfForgingEntries()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug);

        logger.Error(
            "Firewall\r\n[INF] forged-category",
            "operation failed\r\n[ERR] forged-entry",
            errorId: "ERR-1\n[DBG] forged-id");

        string text = File.ReadAllText(path);

        Assert.Contains(@"Firewall\r\n[INF] forged-category", text);
        Assert.Contains(@"operation failed\r\n[ERR] forged-entry", text);
        Assert.Contains(@"ERR-1\n[DBG] forged-id", text);
        Assert.DoesNotContain("\n[ERR] forged-entry", text);
        Assert.DoesNotContain("\n[DBG] forged-id", text);
    }

    [Fact]
    public void Log_WhenTargetFileIsLocked_DoesNotThrowToCaller()
    {
        string path = Path.Combine(_directory, "locked.log");
        File.WriteAllText(path, "seed");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug);

        using var blocker = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);

        Exception? exception = Record.Exception(
            () => logger.Error("Logger", "write while locked"));

        Assert.Null(exception);
    }

    [Fact]
    public void Log_WhenPathIsInvalid_DoesNotThrowToCaller()
    {
        string invalidPath = Path.Combine(_directory, "invalid\0.log");
        var logger = new RotatingFileAppLogger(invalidPath, AppLogLevel.Debug);

        Exception? exception = Record.Exception(
            () => logger.Error("Logger", "invalid destination"));

        Assert.Null(exception);
    }

    [Fact]
    public async Task Log_ConcurrentWritersAndRotation_DoNotThrowOrExceedRetentionLimit()
    {
        string path = Path.Combine(_directory, "concurrent.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug, 512, 3);

        Task[] writers = Enumerable.Range(0, 8)
            .Select(worker => Task.Run(() =>
            {
                for (int index = 0; index < 40; index++)
                {
                    logger.Info($"Worker-{worker}", $"Entry-{index:D3}");
                }
            }))
            .ToArray();

        await Task.WhenAll(writers);

        string[] files = Directory.GetFiles(_directory, "concurrent.log*");
        Assert.InRange(files.Length, 1, 3);
        Assert.Contains(files, file => new FileInfo(file).Length > 0);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
