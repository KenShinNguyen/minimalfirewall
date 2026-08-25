using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Drawing;
using System.Windows.Forms;

namespace MinimalFirewall
{
    internal static class Program
    {
        // ensure single instance across all sessions
        private const string AppGuid = "Global\\6326C497-403B-F991-2F6A-A5FBA67C364C";

        [STAThread]
        static void Main()
        {
            // Setup Global Error Handling
            Application.ThreadException += (s, e) => HandleException(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => HandleException(e.ExceptionObject as Exception);

            using var mutex = new Mutex(true, AppGuid, out bool createdNew);
            if (createdNew)
            {
                Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                Application.SetDefaultFont(new Font("Roboto Mono", 9F, FontStyle.Regular, GraphicsUnit.Point));

                CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
                CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;

                var args = Environment.GetCommandLineArgs();
                bool startMinimized = args.Contains("-tray", StringComparer.OrdinalIgnoreCase);

                var mainForm = new MainForm(startMinimized);
                Application.Run(mainForm);
            }
            else
            {
                MessageBox.Show("Minimal Firewall is already running.", "Application Already Running", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static void HandleException(Exception? ex)
        {
            // Correlates what the user sees in the dialog with the file on disk, so a bug report
            // can be tied to a specific crash without asking the user to reproduce it.
            string errorId = $"MFW-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.CurrentManagedThreadId:X4}";
            string? logPath = TryWriteCrashLog(errorId, ex);

            string message =
                "Minimal Firewall encountered an unexpected error.\n\n" +
                $"Error ID: {errorId}\n" +
                $"{ex?.GetType().Name}: {ex?.Message}\n\n" +
                (logPath != null
                    ? $"Details were saved to:\n{logPath}"
                    : "The crash details could not be written to disk.");

            MessageBox.Show(message, "Unexpected Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        /// <summary>
        /// Writes a full crash report next to the other config files. Returns the path written,
        /// or null when the report could not be saved - logging a crash must never itself crash.
        /// </summary>
        private static string? TryWriteCrashLog(string errorId, Exception? ex)
        {
            try
            {
                string crashDirectory = ConfigPathManager.GetConfigPath("CrashLogs");
                Directory.CreateDirectory(crashDirectory);

                string path = Path.Combine(crashDirectory, $"{errorId}.log");
                var sb = new StringBuilder();

                sb.AppendLine($"Error ID   : {errorId}");
                sb.AppendLine($"Timestamp  : {DateTime.Now:yyyy-MM-dd HH:mm:ss zzz}");
                sb.AppendLine($"App version: {typeof(Program).Assembly.GetName().Version}");
                sb.AppendLine($"OS         : {Environment.OSVersion} ({(Environment.Is64BitOperatingSystem ? "x64" : "x86")})");
                sb.AppendLine($"Process    : {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}, CLR {Environment.Version}");
                sb.AppendLine($"Elevated   : {DescribeElevation()}");
                sb.AppendLine($"Lockdown   : {DescribeLockdownState()}");
                sb.AppendLine();

                int depth = 0;
                for (Exception? current = ex; current != null; current = current.InnerException, depth++)
                {
                    sb.AppendLine(depth == 0 ? "--- Exception ---" : $"--- Inner exception ({depth}) ---");
                    sb.AppendLine($"Type   : {current.GetType().FullName}");
                    sb.AppendLine($"Message: {current.Message}");
                    if (current is System.Runtime.InteropServices.COMException com)
                    {
                        sb.AppendLine($"HResult: 0x{com.HResult:X8}");
                    }
                    sb.AppendLine("Stack  :");
                    sb.AppendLine(current.StackTrace ?? "  (no stack trace)");
                    sb.AppendLine();
                }

                if (ex == null)
                {
                    sb.AppendLine("--- No exception object was supplied ---");
                }

                File.WriteAllText(path, sb.ToString());
                return path;
            }
            catch (Exception writeFailure)
            {
                System.Diagnostics.Debug.WriteLine($"[ERROR] Could not write crash log: {writeFailure.Message}");
                return null;
            }
        }

        private static string DescribeElevation()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator) ? "yes" : "no";
            }
            catch (Exception ex)
            {
                return $"unknown ({ex.GetType().Name})";
            }
        }

        private static string DescribeLockdownState()
        {
            try
            {
                return FirewallRuleService.GetDefaultOutboundState().ToString();
            }
            catch (Exception ex)
            {
                return $"unknown ({ex.GetType().Name})";
            }
        }
    }
}
