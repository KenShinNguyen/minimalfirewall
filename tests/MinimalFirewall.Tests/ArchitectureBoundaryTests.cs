using System;
using System.Collections.Generic;
using System.IO;
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

        var violations = new List<string>();

        foreach (var file in sourceFiles)
        {
            var relativePath = Path.GetRelativePath(sourceRoot, file);
            var fileName = Path.GetFileName(file);
            var content = File.ReadAllText(file);

            foreach (var token in forbiddenEverywhere)
            {
                CollectViolations(content, relativePath, token, violations);
            }

            if (fileName.StartsWith("Windows", StringComparison.Ordinal) &&
                fileName.EndsWith("Backend.cs", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var token in forbiddenOutsideWindowsBackend)
            {
                CollectViolations(content, relativePath, token, violations);
            }
        }

        Assert.True(
            violations.Count == 0,
            "Architecture boundary violations found:\n" +
            string.Join("\n", violations));
    }

    private static void CollectViolations(
        string content,
        string relativePath,
        string token,
        List<string> violations)
    {
        var lines = content.Split('\n');

        for (int index = 0; index < lines.Length; index++)
        {
            if (lines[index].Contains(token, StringComparison.Ordinal))
            {
                violations.Add($"{relativePath}:{index + 1} -> {token}");
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
