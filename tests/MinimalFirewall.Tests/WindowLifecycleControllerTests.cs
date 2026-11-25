using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class WindowLifecycleControllerTests
{
    [Theory]
    [InlineData(true, CloseReason.UserClosing, false)]
    [InlineData(false, CloseReason.UserClosing, true)]
    [InlineData(true, CloseReason.WindowsShutDown, true)]
    [InlineData(true, CloseReason.ApplicationExitCall, true)]
    public void ShouldExitApplication_RespectsCloseToTrayPolicy(
        bool closeToTray,
        CloseReason closeReason,
        bool expected)
    {
        bool actual = WindowLifecycleController.ShouldExitApplication(closeToTray, closeReason);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(FormWindowState.Minimized, FormWindowState.Normal)]
    [InlineData(FormWindowState.Normal, FormWindowState.Normal)]
    [InlineData(FormWindowState.Maximized, FormWindowState.Maximized)]
    public void NormalizeSavedWindowState_DoesNotRestoreMinimizedWindow(
        FormWindowState savedState,
        FormWindowState expected)
    {
        FormWindowState actual = WindowLifecycleController.NormalizeSavedWindowState(savedState);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(false, false, false, true)]
    [InlineData(true, false, true, true)]
    [InlineData(false, true, true, true)]
    [InlineData(false, false, true, true)]
    public void ShouldSkipTimerCallback_BlocksDisposedOrMissingHandle(
        bool controllerDisposed,
        bool formDisposed,
        bool handleCreated,
        bool expected)
    {
        bool actual = WindowLifecycleController.ShouldSkipTimerCallback(
            controllerDisposed,
            formDisposed,
            handleCreated);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task ExecuteOperationSafelyAsync_CatchesExceptionAfterAwait_AndDoesNotEscape()
    {
        var logger = new RecordingUserActivityLogger();
        using var form = new System.Windows.Forms.Form();
        using var controller = new WindowLifecycleController(
            form,
            new AppSettings(),
            logger,
            canRefreshRules: () => true,
            refreshRules: () => Task.CompletedTask);

        await controller.ExecuteOperationSafelyAsync(
            async () =>
            {
                await Task.Yield();
                throw new InvalidOperationException("post-await failure");
            });

        Assert.Single(logger.Exceptions);
        Assert.Contains("post-await failure", logger.Exceptions[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExecuteOperationSafelyAsync_DoesNotLogCancellation()
    {
        var logger = new RecordingUserActivityLogger();
        using var form = new System.Windows.Forms.Form();
        using var controller = new WindowLifecycleController(
            form,
            new AppSettings(),
            logger,
            canRefreshRules: () => true,
            refreshRules: () => Task.CompletedTask);

        await controller.ExecuteOperationSafelyAsync(
            () => throw new OperationCanceledException());

        Assert.Empty(logger.Exceptions);
    }

    private sealed class RecordingUserActivityLogger : UserActivityLogger
    {
        public List<string> Exceptions { get; } = [];

        public override void LogException(string context, Exception ex)
            => Exceptions.Add($"{context}: {ex.Message}");
    }
}
