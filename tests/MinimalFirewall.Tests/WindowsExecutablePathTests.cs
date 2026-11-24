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
}
