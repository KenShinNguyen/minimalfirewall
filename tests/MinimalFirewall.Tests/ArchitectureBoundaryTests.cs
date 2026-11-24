using System;
using System.IO;
using System.Linq;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class ArchitectureBoundaryTests
{
    [Fact]
    public void ComOwnership_IsRestrictedToWindowsBackendSources()
    {
        var sourceRoot = FindSourceRoot();
        var sourceFiles = Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories);

        var forbiddenEverywhere = new[]
        {
            "FirewallRuleHandle",
            "FirewallRuleService"
        };

        var forbiddenOutsideWindowsBackend = new[]
        {
            "NetFwTypeLib",
            "HNetCfg",
            "INetFw",
            "NET_FW_",
            "Marshal.ReleaseComObject"
        };

        foreach (var file in sourceFiles)
        {
            var relativePath = Path.GetRelativePath(sourceRoot, file);
            var fileName = Path.GetFileName(file);
            var content = File.ReadAllText(file);

            foreach (var token in forbiddenEverywhere)
            {
                Assert.DoesNotContain(
                    token,
                    content,
                    StringComparison.Ordinal);
            }

            if (fileName.StartsWith("Windows", StringComparison.Ordinal) &&
                fileName.EndsWith("Backend.cs", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var token in forbiddenOutsideWindowsBackend)
            {
                Assert.DoesNotContain(
                    token,
                    content,
                    StringComparison.Ordinal);
            }
        }
    }

    private static string FindSourceRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory != null)
        {
            var src = Path.Combine(directory.FullName, "src");
            var tests = Path.Combine(directory.FullName, "tests");

            if (Directory.Exists(src) && Directory.Exists(tests))
            {
                return src;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"Could not locate repository source root from '{AppContext.BaseDirectory}'.");
    }
}
