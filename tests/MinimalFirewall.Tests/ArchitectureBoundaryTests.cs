using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
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

    [Fact]
    public void ConcreteWindowsBackendConstruction_IsRestrictedToCompositionRoot()
    {
        var sourceRoot = FindSourceRoot();
        var sourceFiles = Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories);
        var violations = new List<string>();

        foreach (var file in sourceFiles)
        {
            var relativePath = Path.GetRelativePath(sourceRoot, file);
            var content = File.ReadAllText(file);
            violations.AddRange(FindWindowsBackendConstructionViolations(relativePath, content));
        }

        Assert.True(
            violations.Count == 0,
            "Concrete Windows firewall backends may only be constructed inside " +
            "MainForm.InitializeServices() (the composition root):\n" +
            string.Join("\n", violations));
    }

    [Fact]
    public void ConcreteWindowsBackendConstructionGate_AllowsCompositionRootAndRejectsFeatureCode()
    {
        var fixture = string.Join(
            Environment.NewLine,
            "private void InitializeServices()",
            "{",
            "    // A comment is not a dependency.",
            "    var backend = new WindowsFirewallRuleQueryBackend();",
            "    var note = \"new WindowsFirewallRuleCreationBackend();\";",
            "}",
            "private void RefreshRules()",
            "{",
            "    var backend = new WindowsFirewallRuleUpdateBackend();",
            "}");

        var violations = FindWindowsBackendConstructionViolations("MainForm.cs", fixture);

        var violation = Assert.Single(violations);
        Assert.Contains("MainForm.cs:8", violation, StringComparison.Ordinal);
        Assert.Contains("WindowsFirewallRuleUpdateBackend", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void TrayImplementationWiring_IsOwnedByTrayIconController()
    {
        var sourceRoot = FindSourceRoot();
        var mainFormPath = Path.Combine(sourceRoot, "MainForm.cs");
        var trayControllerPath = Path.Combine(sourceRoot, "TrayIconController.cs");

        var mainFormViolations = FindTrayOwnershipViolations(File.ReadAllText(mainFormPath));
        Assert.Empty(mainFormViolations);

        var trayControllerCode = MaskCommentsAndLiterals(File.ReadAllText(trayControllerPath));
        Assert.Matches(@@"\bnew\s+ContextMenuStrip\s*\(", trayControllerCode);
        Assert.Matches(@@"\.\s*Opening\s*\+=", trayControllerCode);
        Assert.Matches(@@"\.\s*DoubleClick\s*\+=", trayControllerCode);
    }

    [Fact]
    public void TrayOwnershipGate_FlagsRegressedMainFormWiring()
    {
        var fixture = string.Join(
            Environment.NewLine,
            "var menu = new ContextMenuStrip();",
            "menu.Opening += OnMenuOpening;",
            "notifyIcon.DoubleClick += ShowWindow;");

        var violations = FindTrayOwnershipViolations(fixture);

        Assert.Equal(3, violations.Count);
        Assert.Contains(violations, violation => violation.Contains("ContextMenuStrip", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("Opening", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("DoubleClick", StringComparison.Ordinal));
    }

    private static IReadOnlyList<string> FindWindowsBackendConstructionViolations(
        string relativePath,
        string source)
    {
        var code = MaskCommentsAndLiterals(source);
        var compositionRoot = string.Equals(
            relativePath.Replace('\\', '/'),
            "MainForm.cs",
            StringComparison.OrdinalIgnoreCase)
            ? FindMethodBody(code, "InitializeServices")
            : null;

        var violations = new List<string>();
        var matches = Regex.Matches(
            code,
            @"\bnew\s+(?<type>Windows[A-Za-z0-9_]*Backend)\s*\(");

        foreach (Match match in matches)
        {
            bool insideCompositionRoot = compositionRoot is { } body &&
                match.Index >= body.Start &&
                match.Index < body.End;

            if (!insideCompositionRoot)
            {
                var backendType = match.Groups["type"].Value;
                violations.Add(
                    $"{relativePath}:{GetLineNumber(source, match.Index)} -> {backendType}");
            }
        }

        return violations;
    }

    private static IReadOnlyList<string> FindTrayOwnershipViolations(string source)
    {
        var code = MaskCommentsAndLiterals(source);
        var violations = new List<string>();

        AddPatternViolations(
            code,
            @"\bnew\s+(?:global::)?(?:System\.Windows\.Forms\.)?ContextMenuStrip\s*\(",
            "ContextMenuStrip construction",
            violations);
        AddPatternViolations(code, @"\.\s*Opening\s*\+=", "ContextMenuStrip.Opening subscription", violations);
        AddPatternViolations(code, @"\.\s*DoubleClick\s*\+=", "NotifyIcon.DoubleClick subscription", violations);

        return violations;
    }

    private static void AddPatternViolations(
        string code,
        string pattern,
        string description,
        List<string> violations)
    {
        foreach (Match match in Regex.Matches(code, pattern))
        {
            violations.Add($"{description} at line {GetLineNumber(code, match.Index)}");
        }
    }

    private static (int Start, int End)? FindMethodBody(string code, string methodName)
    {
        var declaration = Regex.Match(
            code,
            $@"\b{Regex.Escape(methodName)}\s*\(\s*\)\s*\{{");

        if (!declaration.Success)
        {
            return null;
        }

        int openingBrace = code.IndexOf('{', declaration.Index);
        int closingBrace = FindMatchingBrace(code, openingBrace);

        return closingBrace < 0
            ? null
            : (openingBrace + 1, closingBrace);
    }

    private static int FindMatchingBrace(string code, int openingBrace)
    {
        int depth = 0;

        for (int index = openingBrace; index < code.Length; index++)
        {
            if (code[index] == '{')
            {
                depth++;
            }
            else if (code[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
    }

    // Mask comments and string/character literals while preserving offsets and
    // line breaks. This keeps source-based architecture checks from matching
    // examples in comments or strings and lets brace matching remain stable.
    private static string MaskCommentsAndLiterals(string source)
    {
        var masked = source.ToCharArray();
        int index = 0;

        while (index < source.Length)
        {
            if (source[index] == '/' && index + 1 < source.Length)
            {
                if (source[index + 1] == '/')
                {
                    int end = source.IndexOf('\n', index);
                    MaskRange(masked, index, end < 0 ? source.Length : end);
                    index = end < 0 ? source.Length : end;
                    continue;
                }

                if (source[index + 1] == '*')
                {
                    int close = source.IndexOf("*/", index + 2, StringComparison.Ordinal);
                    int end = close < 0 ? source.Length : close + 2;
                    MaskRange(masked, index, end);
                    index = end;
                    continue;
                }
            }

            int literalStart = index;
            int quoteIndex = index;

            if (source[index] is '$' or '@')
            {
                while (quoteIndex < source.Length && source[quoteIndex] is '$' or '@')
                {
                    quoteIndex++;
                }
            }

            if (quoteIndex < source.Length && source[quoteIndex] is '"' or '\'')
            {
                char quote = source[quoteIndex];
                int quoteCount = 1;
                while (quote == '"' &&
                    quoteIndex + quoteCount < source.Length &&
                    source[quoteIndex + quoteCount] == '"')
                {
                    quoteCount++;
                }

                int end = quoteIndex + quoteCount;

                if (quote == '"' && quoteCount >= 3)
                {
                    string delimiter = new('"', quoteCount);
                    int close = source.IndexOf(delimiter, end, StringComparison.Ordinal);
                    end = close < 0 ? source.Length : close + quoteCount;
                }
                else
                {
                    bool verbatim = source.AsSpan(literalStart, quoteIndex - literalStart).Contains('@');
                    while (end < source.Length)
                    {
                        if (verbatim && source[end] == '"' && end + 1 < source.Length && source[end + 1] == '"')
                        {
                            end += 2;
                            continue;
                        }

                        if (!verbatim && source[end] == '\\')
                        {
                            end = Math.Min(end + 2, source.Length);
                            continue;
                        }

                        if (source[end] == quote)
                        {
                            end++;
                            break;
                        }

                        end++;
                    }
                }

                MaskRange(masked, literalStart, end);
                index = end;
                continue;
            }

            index++;
        }

        return new string(masked);
    }

    private static void MaskRange(char[] source, int start, int end)
    {
        for (int index = start; index < end; index++)
        {
            if (source[index] is not '\r' and not '\n')
            {
                source[index] = ' ';
            }
        }
    }

    private static int GetLineNumber(string source, int position)
    {
        int line = 1;
        for (int index = 0; index < position; index++)
        {
            if (source[index] == '\n')
            {
                line++;
            }
        }

        return line;
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
