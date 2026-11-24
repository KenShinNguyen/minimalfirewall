using DarkModeForms;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System;

namespace MinimalFirewall
{
    public static partial class AdminTaskService
    {
        public static void ResetFirewall() =>
            ResetFirewall(new WindowsFirewallPolicyAdminBackend());

        public static void ResetFirewall(IFirewallPolicyAdminBackend backend) =>
            ResetFirewall(backend, (message, title, buttons, icon) => Messenger.MessageBox(message, title, buttons, icon));

        public static void ResetFirewall(
            IFirewallPolicyAdminBackend backend,
            Action<string, string, MessageBoxButtons, MessageBoxIcon> showMessageBox)
        {
            ArgumentNullException.ThrowIfNull(backend);
            ArgumentNullException.ThrowIfNull(showMessageBox);

            var result = backend.ResetFirewall();
            if (result.Succeeded)
            {
                return;
            }

            string error = result.Exception?.Message
                ?? result.Error
                ?? "Unknown error.";

            Debug.WriteLine($"[AdminTask ERROR] Firewall reset failed: {error}");
            showMessageBox(
                $"Could not reset Windows Firewall.\n\nError: {error}",
                "Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        public static void SetAuditPolicy(bool enable)
        {
            string[] guids =
            [
                "{0CCE9225-69AE-11D9-BED3-505054503030}",
                "{0CCE9226-69AE-11D9-BED3-505054503030}"
            ];
            foreach (var guid in guids)
            {
                string arguments = $"/set /subcategory:{guid} /failure:{(enable ? "enable" : "disable")}";
                Execute(arguments, Path.Combine(Environment.SystemDirectory, "auditpol.exe"), out _);
            }
        }

        public static bool IsAuditPolicyEnabled()
        {
            var packetDropGuid = new Guid("{0CCE9225-69AE-11D9-BED3-505054503030}");
            var connectionGuid = new Guid("{0CCE9226-69AE-11D9-BED3-505054503030}");

            return IsAuditingEnabledForSubcategory(packetDropGuid) && IsAuditingEnabledForSubcategory(connectionGuid);
        }

        public static bool IsWfpConnectionAuditPolicyEnabled()
        {
            var connectionGuid = new Guid("{0CCE9226-69AE-11D9-BED3-505054503030}");
            return IsAuditingEnabledForSubcategory(connectionGuid);
        }

        private const uint AUDIT_FAILURE = 0x00000002;

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool AuditQuerySystemPolicy(
            ref Guid pSubCategoryGuids,
            uint PolicyCount,
            out IntPtr ppPolicy
        );

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool AuditFree(
            IntPtr pBuffer
        );

        [StructLayout(LayoutKind.Sequential)]
        private struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public uint AuditingInformation;
        }

        private static bool IsAuditingEnabledForSubcategory(Guid subcategoryGuid)
        {
            if (!AuditQuerySystemPolicy(ref subcategoryGuid, 1, out IntPtr pPolicy))
            {
                int error = Marshal.GetLastWin32Error();
                Debug.WriteLine($"[AdminTask ERROR] AuditQuerySystemPolicy failed for GUID {subcategoryGuid}, Win32 Error: {error}");
                return false;
            }

            try
            {
                var policyInfo = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(pPolicy);
                return (policyInfo.AuditingInformation & AUDIT_FAILURE) == AUDIT_FAILURE;
            }
            finally
            {
                if (pPolicy != IntPtr.Zero)
                {
                    AuditFree(pPolicy);
                }
            }
        }

        private static void Execute(string arguments, string fileName, out string? output)
        {
            Debug.WriteLine($"[AdminTask] Preparing to execute: {fileName} {arguments}");
            output = null;
            var startInfo = new ProcessStartInfo()
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            try
            {
                using var process = new Process { StartInfo = startInfo };
                var outputBuilder = new StringBuilder();
                var errorBuilder = new StringBuilder();

                using var outputWaitHandle = new AutoResetEvent(false);
                using var errorWaitHandle = new AutoResetEvent(false);
                process.OutputDataReceived += (sender, e) =>
                {
                    if (e.Data == null)
                    {
                        outputWaitHandle.Set();
                    }
                    else
                    {
                        outputBuilder.AppendLine(e.Data);
                    }
                };
                process.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data == null)
                    {
                        errorWaitHandle.Set();
                    }
                    else
                    {
                        errorBuilder.AppendLine(e.Data);
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                if (process.WaitForExit(5000) && outputWaitHandle.WaitOne(5000) && errorWaitHandle.WaitOne(5000))
                {
                    output = outputBuilder.ToString();
                    string errors = errorBuilder.ToString();

                    Debug.WriteLine($"[AdminTask] Exit Code: {process.ExitCode}");
                    if (!string.IsNullOrWhiteSpace(errors))
                    {
                        Messenger.MessageBox($"An error occurred during an administrative task:\n\n{errors}", "Admin Task Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                else
                {
                    Debug.WriteLine("[AdminTask ERROR] Process timed out or streams did not close.");
                    try
                    {
                        if (!process.HasExited)
                        {
                            process.Kill();
                        }
                    }
                    catch { /* Ignore errors if process already died */ }

                    Messenger.MessageBox("An administrative task timed out and may not have completed successfully.", "Execution Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or ObjectDisposedException or InvalidOperationException)
            {
                Debug.WriteLine($"[AdminTask FATAL ERROR] {ex}");
                Messenger.MessageBox($"A critical error occurred while trying to run an administrative task:\n\n{ex.Message}", "Execution Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    public class StartupService
    {
        private const string RegistryKeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        private readonly string? _appName;
        private readonly string? _appPath;
        private readonly string _taskName;

        public StartupService()
        {
            _appName = Assembly.GetExecutingAssembly().GetName().Name;
            _appPath = Environment.ProcessPath;
            if (_appName != null)
            {
                _taskName = _appName + " Startup";
            }
            else
            {
                _taskName = "MinimalFirewall Startup";
            }
        }

        public void SetStartup(bool isEnabled)
        {
            if (string.IsNullOrEmpty(_appName) || string.IsNullOrEmpty(_appPath))
            {
                return;
            }

            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegistryKeyPath, true);
                if (key?.GetValue(_appName) != null)
                {
                    key.DeleteValue(_appName, false);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Startup] Failed to remove old registry key: {ex.Message}");
            }

            if (isEnabled)
            {
                string arguments = $"/create /tn \"{_taskName}\" /tr \"\\\"{_appPath}\\\" -tray\" /sc onlogon /rl highest /f";
                Execute("schtasks.exe", arguments, out _, out _);
            }
            else
            {
                string arguments = $"/delete /tn \"{_taskName}\" /f";
                Execute("schtasks.exe", arguments, out _, out _);
            }
        }

        public void VerifyAndCorrectStartupTaskPath()
        {
            if (string.IsNullOrEmpty(_taskName) || string.IsNullOrEmpty(_appPath))
            {
                return;
            }

            string arguments = $"/query /tn \"{_taskName}\" /v /fo CSV /nh";
            Execute("schtasks.exe", arguments, out string? output, out string? error);

            if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(output))
            {
                Debug.WriteLine($"[Startup] Could not query task '{_taskName}'. It might not exist. Error: {error}");
                return;
            }
            try
            {
                var parts = output.Split('"');
                string storedPath = string.Empty;
                foreach (var part in parts)
                {
                    if (part.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        storedPath = part;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(storedPath))
                {
                    Debug.WriteLine($"[Startup] Could not parse executable path from schtasks output: {output}");
                    return;
                }

                string normalizedStoredPath = PathResolver.NormalizePath(storedPath);
                string normalizedCurrentPath = PathResolver.NormalizePath(_appPath);

                if (!normalizedStoredPath.Equals(normalizedCurrentPath, StringComparison.OrdinalIgnoreCase))
                {
                    Debug.WriteLine($"[Startup] Mismatch detected. Stored: '{normalizedStoredPath}', Current: '{normalizedCurrentPath}'. Correcting task.");
                    SetStartup(true);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Startup] Error during startup path verification: {ex.Message}");
            }
        }

        private static void Execute(string fileName, string arguments, out string output, out string error)
        {
            ProcessHelper.RunHiddenCommand(fileName, arguments, out output, out error);
            if (!string.IsNullOrEmpty(error))
            {
                Debug.WriteLine($"[Startup ERROR]: {error}");
            }
        }
    }

    public static class ProcessHelper
    {
        internal static string GetWindowsSystemExecutablePath(string executableName) =>
            CombineWindowsExecutablePath(Environment.SystemDirectory, executableName);

        internal static string GetWindowsDirectoryExecutablePath(string executableName) =>
            CombineWindowsExecutablePath(Environment.GetFolderPath(Environment.SpecialFolder.Windows), executableName);

        private static string CombineWindowsExecutablePath(string directory, string executableName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(directory);
            ArgumentException.ThrowIfNullOrWhiteSpace(executableName);

            if (Path.IsPathRooted(executableName)
                || !string.Equals(Path.GetFileName(executableName), executableName, StringComparison.Ordinal)
                || executableName is "." or ".."
                || !executableName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("A Windows executable file name without a directory is required.", nameof(executableName));
            }

            if (!Path.IsPathFullyQualified(directory))
            {
                throw new InvalidOperationException("The Windows executable directory is not an absolute path.");
            }

            return Path.Combine(directory, executableName);
        }

        internal static ProcessStartInfo CreateExplorerSelectStartInfo(string targetPath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

            var startInfo = new ProcessStartInfo(GetWindowsDirectoryExecutablePath("explorer.exe"))
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("/select,");
            startInfo.ArgumentList.Add(targetPath.Trim('"'));

            return startInfo;
        }
        public static void RunHiddenCommand(string fileName, string arguments, out string output, out string error)
        {
            string safePath = Path.IsPathRooted(fileName) ? fileName : GetWindowsSystemExecutablePath(fileName);
            Debug.WriteLine($"[ProcessHelper] Executing: {safePath} {arguments}");

            var startInfo = new ProcessStartInfo
            {
                FileName = safePath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            try
            {
                using var process = new Process { StartInfo = startInfo };
                if (!process.Start())
                {
                    output = string.Empty;
                    error = "Failed to start process.";
                    return;
                }

                // Drain both redirected streams concurrently. Reading one stream to completion
                // before starting the other can deadlock when the child fills the unread pipe.
                Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
                Task<string> errorTask = process.StandardError.ReadToEndAsync();
                Task exitTask = process.WaitForExitAsync();
                Task completionTask = Task.WhenAll(outputTask, errorTask, exitTask);

                if (Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5))).GetAwaiter().GetResult() != completionTask)
                {
                    Debug.WriteLine("[ProcessHelper ERROR] Process timed out; terminating the process tree.");
                    try
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(entireProcessTree: true);
                        }
                    }
                    catch (Exception killException) when (killException is InvalidOperationException or System.ComponentModel.Win32Exception or System.NotSupportedException)
                    {
                        Debug.WriteLine($"[ProcessHelper ERROR] Could not terminate timed-out process: {killException.Message}");
                    }

                    try
                    {
                        process.WaitForExit(1000);
                    }
                    catch (InvalidOperationException)
                    {
                        // The process may have exited while it was being terminated.
                    }

                    Task readersTask = Task.WhenAll(outputTask, errorTask);
                    _ = Task.WhenAny(readersTask, Task.Delay(TimeSpan.FromSeconds(1))).GetAwaiter().GetResult();

                    output = outputTask.Status == TaskStatus.RanToCompletion ? outputTask.Result : string.Empty;
                    string capturedError = errorTask.Status == TaskStatus.RanToCompletion ? errorTask.Result : string.Empty;
                    error = string.IsNullOrWhiteSpace(capturedError)
                        ? "Process timed out after 5 seconds."
                        : $"Process timed out after 5 seconds. {capturedError}";
                    return;
                }

                completionTask.GetAwaiter().GetResult();
                output = outputTask.Result;
                error = errorTask.Result;
            }
            catch (Exception ex)
            {
                output = string.Empty;
                error = ex.Message;
                Debug.WriteLine($"[ProcessHelper FATAL ERROR] {ex.Message}");
            }
        }
    }
}
