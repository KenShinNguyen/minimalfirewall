using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace MinimalFirewall
{
    /// <summary>
    /// Phase 5C UI seam for system-tray wiring. MainForm retains lifecycle policy
    /// while this controller owns tray menu construction and event hookups.
    /// </summary>
    internal sealed class TrayIconController : IDisposable
    {
        private readonly NotifyIcon _notifyIcon;
        private readonly ContextMenuStrip _contextMenu;
        private bool _disposed;
        private readonly EventHandler _showWindowHandler;

        internal ToolStripMenuItem LockdownMenuItem { get; }

        internal TrayIconController(
            NotifyIcon notifyIcon,
            Icon? icon,
            EventHandler toggleLockdown,
            EventHandler showWindow,
            EventHandler exitApplication,
            CancelEventHandler menuOpening)
        {
            _notifyIcon = notifyIcon;
            _showWindowHandler = showWindow;
            LockdownMenuItem = new ToolStripMenuItem("Toggle Lockdown", null, toggleLockdown);

            _contextMenu = new ContextMenuStrip();
            _contextMenu.Items.Add(LockdownMenuItem);
            _contextMenu.Items.Add(new ToolStripMenuItem("Show", null, showWindow));
            _contextMenu.Items.Add(new ToolStripMenuItem("Exit", null, exitApplication));
            _contextMenu.Opening += menuOpening;

            _notifyIcon.Icon = icon;
            _notifyIcon.Text = "Minimal Firewall";
            _notifyIcon.Visible = true;
            _notifyIcon.ContextMenuStrip = _contextMenu;
            _notifyIcon.DoubleClick += _showWindowHandler;
        }

        internal void SetIcon(Icon? icon)
        {
            if (!_disposed && icon is not null)
            {
                _notifyIcon.Icon = icon;
            }
        }

        internal void SetVisible(bool visible)
        {
            if (!_disposed)
            {
                _notifyIcon.Visible = visible;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _notifyIcon.Visible = false;
            _notifyIcon.DoubleClick -= _showWindowHandler;
            _notifyIcon.ContextMenuStrip = null;
            _contextMenu.Dispose();
        }
    }
}
