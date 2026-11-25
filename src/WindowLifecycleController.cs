using System;
using System.Drawing;
using System.Linq;
using System.Threading;
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
        private int _disposed;

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
            _autoRefreshTimer = new System.Threading.Timer(
                _ => _ = DispatchRefreshAsync(),
                null,
                interval,
                interval);

            _activityLogger.LogDebug(
                $"Auto-refresh timer set to {_appSettings.AutoRefreshIntervalMinutes} minutes.");
        }

        internal void SaveWindowState()
        {
            ThrowIfDisposed();

            bool isNormal = _form.WindowState == FormWindowState.Normal;
            _appSettings.WindowLocation = isNormal ? _form.Location : _form.RestoreBounds.Location;
            _appSettings.WindowSize = isNormal ? _form.Size : _form.RestoreBounds.Size;
            _appSettings.WindowState = _form.WindowState == FormWindowState.Maximized
                ? (int)FormWindowState.Maximized
                : (int)FormWindowState.Normal;
        }

        internal bool ShouldExit(CloseReason closeReason)
            => ShouldExitApplication(_appSettings.CloseToTray, closeReason);

        internal static bool ShouldExitApplication(bool closeToTray, CloseReason closeReason)
            => !closeToTray || closeReason != CloseReason.UserClosing;

        internal void StopAutoRefreshTimer()
        {
            var timer = Interlocked.Exchange(ref _autoRefreshTimer, null);
            timer?.Dispose();
        }

        internal static bool ShouldSkipTimerCallback(
            bool controllerDisposed,
            bool formDisposed,
            bool handleCreated)
            => controllerDisposed || formDisposed || !handleCreated;

        private async Task DispatchRefreshAsync()
        {
            if (ShouldSkipTimerCallback(
                    Volatile.Read(ref _disposed) != 0,
                    _form.IsDisposed,
                    _form.IsHandleCreated))
            {
                return;
            }

            try
            {
                await _form.InvokeAsync(
                    async cancellationToken =>
                    {
                        if (Volatile.Read(ref _disposed) != 0 ||
                            _form.IsDisposed ||
                            _form.Disposing ||
                            !cancellationToken.IsCancellationRequested &&
                            !_form.IsHandleCreated)
                        {
                            return;
                        }

                        await ExecuteRefreshSafelyAsync(cancellationToken);
                    },
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (InvalidOperationException) when (
                Volatile.Read(ref _disposed) != 0 ||
                _form.IsDisposed ||
                _form.Disposing ||
                !_form.IsHandleCreated)
            {
            }
        }

        private async Task ExecuteRefreshSafelyAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested ||
                Volatile.Read(ref _disposed) != 0 ||
                _form.IsDisposed ||
                _form.Disposing)
            {
                return;
            }

            try
            {
                if (_form.Visible && _canRefreshRules())
                {
                    await _refreshRules().ConfigureAwait(true);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException) when (
                Volatile.Read(ref _disposed) != 0 ||
                _form.IsDisposed ||
                _form.Disposing)
            {
            }
            catch (Exception ex)
            {
                _activityLogger.LogException("WindowLifecycleController.AutoRefresh", ex);
            }
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

            var savedState = NormalizeSavedWindowState((FormWindowState)_appSettings.WindowState);
            _form.WindowState = savedState;
        }

        internal static FormWindowState NormalizeSavedWindowState(FormWindowState savedState)
            => savedState == FormWindowState.Minimized
                ? FormWindowState.Normal
                : savedState;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            StopAutoRefreshTimer();
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, GetType().Name);
        }
    }
}
