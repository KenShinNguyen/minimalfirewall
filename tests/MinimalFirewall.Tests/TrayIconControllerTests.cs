using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class TrayIconControllerTests
{
    [Fact]
    public void Constructor_RejectsNullNotifyIcon()
    {
        Assert.Equal(
            "notifyIcon",
            Assert.Throws<ArgumentNullException>(
                () => CreateController(null!)).ParamName);
    }

    [Fact]
    public void Constructor_RejectsEachRequiredCallback()
    {
        using var notifyIcon = new NotifyIcon();

        Assert.Equal(
            "toggleLockdown",
            Assert.Throws<ArgumentNullException>(
                () => new TrayIconController(
                    notifyIcon,
                    SystemIcons.Application,
                    null!,
                    NoopEventHandler,
                    NoopEventHandler,
                    NoopCancelEventHandler)).ParamName);
        Assert.Equal(
            "showWindow",
            Assert.Throws<ArgumentNullException>(
                () => new TrayIconController(
                    notifyIcon,
                    SystemIcons.Application,
                    NoopEventHandler,
                    null!,
                    NoopEventHandler,
                    NoopCancelEventHandler)).ParamName);
        Assert.Equal(
            "exitApplication",
            Assert.Throws<ArgumentNullException>(
                () => new TrayIconController(
                    notifyIcon,
                    SystemIcons.Application,
                    NoopEventHandler,
                    NoopEventHandler,
                    null!,
                    NoopCancelEventHandler)).ParamName);
        Assert.Equal(
            "menuOpening",
            Assert.Throws<ArgumentNullException>(
                () => new TrayIconController(
                    notifyIcon,
                    SystemIcons.Application,
                    NoopEventHandler,
                    NoopEventHandler,
                    NoopEventHandler,
                    null!)).ParamName);
    }

    [Fact]
    public void Constructor_SetsDefaultIconTextAndThreeMenuItems()
    {
        using var notifyIcon = new NotifyIcon();
        using var controller = CreateController(notifyIcon);

        Assert.True(notifyIcon.Visible);
        Assert.Equal("Minimal Firewall", notifyIcon.Text);
        Assert.NotNull(notifyIcon.Icon);
        Assert.NotNull(notifyIcon.ContextMenuStrip);
        Assert.Equal(3, notifyIcon.ContextMenuStrip!.Items.Count);
        Assert.Equal("Toggle Lockdown", notifyIcon.ContextMenuStrip.Items[0].Text);
        Assert.Equal("Show", notifyIcon.ContextMenuStrip.Items[1].Text);
        Assert.Equal("Exit", notifyIcon.ContextMenuStrip.Items[2].Text);
        Assert.Same(notifyIcon.ContextMenuStrip.Items[0], controller.LockdownMenuItem);
    }

    [Fact]
    public void SetVisible_TogglesNotifyIconVisibilityBothWays()
    {
        using var notifyIcon = new NotifyIcon();
        using var controller = CreateController(notifyIcon);

        controller.SetVisible(false);
        Assert.False(notifyIcon.Visible);

        controller.SetVisible(true);
        Assert.True(notifyIcon.Visible);
    }

    [Fact]
    public void SetIcon_UpdatesIconAndIgnoresNull()
    {
        using var notifyIcon = new NotifyIcon();
        using var controller = CreateController(notifyIcon);

        controller.SetIcon(SystemIcons.Warning);
        Assert.Same(SystemIcons.Warning, notifyIcon.Icon);

        controller.SetIcon(null);
        Assert.Same(SystemIcons.Warning, notifyIcon.Icon);
    }

    [Fact]
    public void MenuItems_InvokeOnlyTheirMatchingCallbacksOnce()
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

        var menu = notifyIcon.ContextMenuStrip!;
        ((ToolStripMenuItem)menu.Items[0]).PerformClick();
        ((ToolStripMenuItem)menu.Items[1]).PerformClick();
        ((ToolStripMenuItem)menu.Items[2]).PerformClick();

        Assert.Equal(1, toggleCalls);
        Assert.Equal(1, showCalls);
        Assert.Equal(1, exitCalls);
    }

    [Fact]
    public void Dispose_HidesNotifyIconAndDetachesContextMenu()
    {
        using var notifyIcon = new NotifyIcon();
        var controller = CreateController(notifyIcon);
        ContextMenuStrip menu = notifyIcon.ContextMenuStrip!;

        controller.Dispose();

        Assert.False(notifyIcon.Visible);
        Assert.Null(notifyIcon.ContextMenuStrip);
        Assert.True(menu.IsDisposed);
        controller.Dispose();
    }

    [Fact]
    public void MethodsAfterDispose_AreNoOpsAndDisposeIsIdempotent()
    {
        using var notifyIcon = new NotifyIcon();
        var controller = CreateController(notifyIcon);
        Icon originalIcon = notifyIcon.Icon!;

        controller.Dispose();
        controller.Dispose();

        controller.SetVisible(true);
        controller.SetIcon(SystemIcons.Error);

        Assert.False(notifyIcon.Visible);
        Assert.Same(originalIcon, notifyIcon.Icon);
        Assert.Null(notifyIcon.ContextMenuStrip);
    }

    private static TrayIconController CreateController(NotifyIcon notifyIcon)
        => new(
            notifyIcon,
            SystemIcons.Application,
            NoopEventHandler,
            NoopEventHandler,
            NoopEventHandler,
            NoopCancelEventHandler);

    private static void NoopEventHandler(object? sender, EventArgs e) { }

    private static void NoopCancelEventHandler(object? sender, CancelEventArgs e) { }
}
