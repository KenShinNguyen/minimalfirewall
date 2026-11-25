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
}
