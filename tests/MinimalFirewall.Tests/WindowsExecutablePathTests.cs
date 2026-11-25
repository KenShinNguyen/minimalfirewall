using System.Diagnostics;
using System.IO;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class WindowsExecutablePathTests
{
    [Fact]
    public void GetWindowsSystemExecutablePath_UsesTheSystemDirectory()
    {
        string path = ProcessHelper.GetWindowsSystemExecutablePath("powershell.exe");

        Assert.Equal(
            Path.Combine(Environment.SystemDirectory, "powershell.exe"),
            path);
        Assert.True(Path.IsPathFullyQualified(path));
    }

    [Fact]
    public void GetWindowsDirectoryExecutablePath_UsesTheWindowsDirectory()
    {
        string windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string path = ProcessHelper.GetWindowsDirectoryExecutablePath("explorer.exe");

        Assert.Equal(Path.Combine(windowsDirectory, "explorer.exe"), path);
        Assert.True(Path.IsPathFullyQualified(path));
    }

    [Theory]
    [InlineData(@"..\powershell.exe")]
    [InlineData(@"C:\Windows\System32\powershell.exe")]
    [InlineData("powershell.txt")]
    [InlineData("..")]
    public void GetWindowsSystemExecutablePath_RejectsPathsAndNonExecutables(string executableName)
    {
        Assert.Throws<ArgumentException>(
            () => ProcessHelper.GetWindowsSystemExecutablePath(executableName));
    }

    [Fact]
    public void CreateExplorerSelectStartInfo_UsesAbsoluteExplorerPathAndArgumentList()
    {
        const string targetPath = @"C:\Program Files\Example App\Example.exe";

        ProcessStartInfo startInfo = ProcessHelper.CreateExplorerSelectStartInfo(targetPath);

        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
            startInfo.FileName);
        Assert.True(Path.IsPathFullyQualified(startInfo.FileName));
        Assert.False(startInfo.UseShellExecute);
        Assert.Equal(new[] { "/select,", targetPath }, startInfo.ArgumentList);
    }

    [Fact]
    public void CreateExplorerSelectStartInfo_RemovesLegacySurroundingQuotes()
    {
        const string targetPath = @"C:\Program Files\Example App\Example.exe";

        ProcessStartInfo startInfo = ProcessHelper.CreateExplorerSelectStartInfo($"\"{targetPath}\"");

        Assert.Equal(new[] { "/select,", targetPath }, startInfo.ArgumentList);
    }

    [Fact]
    public void ResolveExecutablePath_RejectsUncAndDriveRelativePaths()
    {
        Assert.Throws<ArgumentException>(
            () => ProcessHelper.ResolveExecutablePath(@"\\server\share\cmd.exe"));
        Assert.Throws<ArgumentException>(
            () => ProcessHelper.ResolveExecutablePath(@"C:cmd.exe"));
    }

    [Fact]
    public void ResolveExecutablePath_PreservesFullyQualifiedExtendedLengthLocalPath()
    {
        const string extendedPath = @"\\?\C:\Windows\System32\cmd.exe";

        string actual = ProcessHelper.ResolveExecutablePath(extendedPath);

        Assert.Equal(extendedPath, actual);
        Assert.True(Path.IsPathFullyQualified(actual));
    }

    [Fact]
    public void RunHiddenCommand_WhenExecutableDoesNotExist_ReturnsControlledFailure()
    {
        string missingPath = Path.Combine(
            Path.GetTempPath(),
            $"mfw-missing-{Guid.NewGuid():N}.exe");

        string output = string.Empty;
        string failure = string.Empty;
        Exception? thrown = Record.Exception(
            () => ProcessHelper.RunHiddenCommand(missingPath, string.Empty, out output, out failure));

        Assert.Null(thrown);
        Assert.Empty(output);
        Assert.Contains("not found", failure, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RunHiddenCommand_WhenPathExceedsLegacyMaxPath_ReturnsControlledFailure()
    {
        string longDirectory = new string('x', 280);
        string longPath = Path.Combine(Path.GetTempPath(), longDirectory, "missing.exe");

        string output = string.Empty;
        string error = string.Empty;
        Exception? thrown = Record.Exception(
            () => ProcessHelper.RunHiddenCommand(longPath, string.Empty, out output, out error));

        Assert.Null(thrown);
        Assert.Empty(output);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void RunHiddenCommand_DrainsStandardOutputAndErrorConcurrently()
    {
        string commandPath = ProcessHelper.GetWindowsSystemExecutablePath("cmd.exe");
        string arguments = "/d /c \"for /L %i in (1,1,5000) do (echo stdout-1234567890& echo stderr-1234567890 1>&2)\"";

        ProcessHelper.RunHiddenCommand(commandPath, arguments, out string output, out string error);

        Assert.Contains("stdout-1234567890", output);
        Assert.Contains("stderr-1234567890", error);
        Assert.DoesNotContain("timed out", error, StringComparison.OrdinalIgnoreCase);
    }


}
