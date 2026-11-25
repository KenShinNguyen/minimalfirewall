using System;
using System.Drawing;
using System.Windows.Forms;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class TrayIconControllerTests
{
    [Fact]
    public void Constructor_WiresTrayMenuAndShowsIcon()
    {
        using var notifyIcon = new NotifyIcon();
        int toggleCalls = 0;
        int showCalls = 0;
        int exitCalls = 0;

        using var controller = new TrayIconController(
            notifyIcon,
            SystemIcons.Application,
            (_, _) => toggleCalls++,
            (_, _) => showCalls++,
            (_, _) => exitCalls++,
            (_, _) => { });

        Assert.True(notifyIcon.Visible);
        Assert.Equal("Minimal Firewall", notifyIcon.Text);
        Assert.NotNull(notifyIcon.ContextMenuStrip);
        Assert.Equal(3, notifyIcon.ContextMenuStrip!.Items.Count);
        Assert.Equal("Toggle Lockdown", controller.LockdownMenuItem.Text);
    }

    [Fact]
    public void SetVisible_AndSetIcon_UpdateNotifyIconUntilDisposed()
    {
        using var notifyIcon = new NotifyIcon();
        using var controller = new TrayIconController(
            notifyIcon,
            SystemIcons.Application,
            (_, _) => { },
            (_, _) => { },
            (_, _) => { },
            (_, _) => { });

        controller.SetVisible(false);
        Assert.False(notifyIcon.Visible);

        controller.SetVisible(true);
        Assert.True(notifyIcon.Visible);

        controller.SetIcon(SystemIcons.Warning);
        Assert.Equal(SystemIcons.Warning, notifyIcon.Icon);

        controller.Dispose();

        Assert.False(notifyIcon.Visible);

        controller.SetVisible(true);
        controller.SetIcon(SystemIcons.Error);

        Assert.False(notifyIcon.Visible);
        Assert.Equal(SystemIcons.Warning, notifyIcon.Icon);
    }

    [Fact]
    public void Dispose_IsIdempotent_AndDetachesShowHandler()
    {
        using var notifyIcon = new NotifyIcon();
        int showCalls = 0;

        using var controller = new TrayIconController(
            notifyIcon,
            SystemIcons.Application,
            (_, _) => { },
            (_, _) => showCalls++,
            (_, _) => { },
            (_, _) => { });

        controller.Dispose();
        controller.Dispose();

        Assert.False(notifyIcon.Visible);
        Assert.Null(notifyIcon.ContextMenuStrip);
        Assert.NotNull(controller.LockdownMenuItem);

        notifyIcon.Dispose();
        Assert.Equal(0, showCalls);
    }
}
