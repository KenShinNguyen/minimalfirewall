using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MinimalFirewall
{
    internal sealed class WindowLifecycleController : IDisposable
    {
        private readonly Form _form;
        private readonly AppSettings _appSettings;
        private readonly UserActivityLogger _activityLogger;
        private readonly Func<bool> _canRefreshRules;
        private readonly Func<Task> _refreshRules;
        private System.Threading.Timer? _autoRefreshTimer;
        private bool _disposed;

        internal WindowLifecycleController(
            Form form,
            AppSettings appSettings,
            UserActivityLogger activityLogger,
            Func<bool> canRefreshRules,
            Func<Task> refreshRules)
        {
            _form = form;
            _appSettings = appSettings;
            _activityLogger = activityLogger;
            _canRefreshRules = canRefreshRules;
            _refreshRules = refreshRules;
        }

        internal void SetupAutoRefreshTimer()
        {
            ThrowIfDisposed();

            _autoRefreshTimer?.Dispose();
            _autoRefreshTimer = null;

            if (_appSettings.AutoRefreshIntervalMinutes <= 0)
            {
                return;
            }

            var interval = TimeSpan.FromMinutes(_appSettings.AutoRefreshIntervalMinutes);
            _autoRefreshTimer = new System.Threading.Timer(_ =>
            {
                if (_form.IsDisposed || !_form.IsHandleCreated)
                {
                    return;
                }

                try
                {
                    _form.Invoke(new Action(async () =>
                    {
                        if (_form.Visible && _canRefreshRules())
                        {
                            await _refreshRules();
                        }
                    }));
                }
                catch (ObjectDisposedException)
                {
                }
            }, null, interval, interval);

            _activityLogger.LogDebug(
                $"Auto-refresh timer set to {_appSettings.AutoRefreshIntervalMinutes} minutes.");
        }

        internal void ApplyLastWindowState()
        {
            ThrowIfDisposed();

            if (_appSettings.WindowSize.Width > 0 && _appSettings.WindowSize.Height > 0)
            {
                _form.Size = _appSettings.WindowSize;
            }

            bool isVisible = Screen.AllScreens.Any(
                screen => screen.WorkingArea.Contains(_appSettings.WindowLocation));

            if (isVisible)
            {
                _form.Location = _appSettings.WindowLocation;
            }
            else
            {
                _form.StartPosition = FormStartPosition.CenterScreen;
            }

            var savedState = (FormWindowState)_appSettings.WindowState;
            if (savedState == FormWindowState.Minimized)
            {
                savedState = FormWindowState.Normal;
            }

            _form.WindowState = savedState;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _autoRefreshTimer?.Dispose();
            _autoRefreshTimer = null;
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType().Name);
        }
    }
}
