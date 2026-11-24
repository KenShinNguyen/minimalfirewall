using System;
using System.IO;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class RotatingFileAppLoggerTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "MinimalFirewallTests", Guid.NewGuid().ToString("N"));
    public RotatingFileAppLoggerTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void Log_WhenExceedingMaxFileBytes_RotatesAndKeepsAtMostThreeFiles()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug, 256, 3);
        for (int i = 0; i < 10; i++) logger.Info("Test", new string((char)('A' + i), 220));
        string[] files = Directory.GetFiles(_directory, "test.log*");
        Assert.True(files.Length <= 3);
        Assert.DoesNotContain(files, f => f.EndsWith(".3", StringComparison.Ordinal));
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
    public void Log_WithErrorIdAndException_FormatsStructuredLine()
    {
        string path = Path.Combine(_directory, "test.log");
        var logger = new RotatingFileAppLogger(path, AppLogLevel.Debug);
        logger.Error("Test", "failure", new InvalidOperationException("boom"), "ERR-12345678");
        string text = File.ReadAllText(path);
        Assert.Contains("[ERR]", text); Assert.Contains("[Test]", text); Assert.Contains("[ERR-12345678]", text);
        Assert.Contains("failure", text); Assert.Contains("InvalidOperationException", text);
    }

    public void Dispose() { try { Directory.Delete(_directory, true); } catch { } }
}
