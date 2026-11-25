using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using Xunit;

namespace MinimalFirewall.Tests.Architecture;

public sealed class ArchitectureBoundaryNegativeFixtureTests
{
    private static readonly HashSet<string> EmptyAllowList = new(StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void SourceRule_DetectsConcreteBackend_OutsideInitializeServices()
    {
        const string violatingMainForm = """
            public partial class MainForm
            {
                public MainForm()
                {
                    InitializeServices();
                }

                private void InitializeServices()
                {
                    var approved = new WindowsFirewallBackend();
                }

                private void OnButtonClick()
                {
                    var leak = new WindowsFirewallBackend();
                }
            }
            """;

        var documents = new[] { new SourceDocument("MainForm.cs", violatingMainForm) };
        var exceptions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["MainForm.cs"] = ["InitializeServices"]
        };

        var violations = ArchitectureBoundaryEvaluator.FindForbiddenSourceTokens(
            documents,
            forbiddenIdentifiers: ["WindowsFirewallBackend"],
            allowedFileNames: EmptyAllowList,
            scopedMethodExceptions: exceptions);

        string violation = Assert.Single(violations);
        Assert.Contains("MainForm.cs:15", violation, StringComparison.Ordinal);
        Assert.Contains("WindowsFirewallBackend", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void SourceRule_AllowsConcreteBackend_OnlyInsideInitializeServices()
    {
        const string validMainForm = """
            public partial class MainForm
            {
                public MainForm()
                {
                    InitializeServices();
                }

                private void InitializeServices()
                {
                    var policy = new WindowsFirewallBackend();
                    var lifecycle = new WindowsFirewallRuleLifecycleBackend();
                }

                private void OnButtonClick()
                {
                    RefreshRules();
                }
            }
            """;

        var documents = new[] { new SourceDocument("MainForm.cs", validMainForm) };
        var exceptions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["MainForm.cs"] = ["InitializeServices"]
        };

        var violations = ArchitectureBoundaryEvaluator.FindForbiddenSourceTokens(
            documents,
            forbiddenIdentifiers:
            [
                "WindowsFirewallBackend",
                "WindowsFirewallRuleLifecycleBackend"
            ],
            allowedFileNames: EmptyAllowList,
            scopedMethodExceptions: exceptions);

        Assert.Empty(violations);
    }

    [Fact]
    public void SourceRule_IgnoresCommentsAndStringLiterals_WithoutChangingLineCoordinates()
    {
        string source =
            "// WindowsFirewallBackend comment\r\n" +
            "/* WindowsFirewallRuleLifecycleBackend block */\r\n" +
            "var empty = \"\";\r\n" +
            "var normal = \"WindowsFirewallBackend\";\r\n" +
            "var verbatim = @\"WindowsFirewallRuleLifecycleBackend\";\r\n" +
            "var verbatimQuote = @\"\"\"\";\r\n" +
            "var raw = \"\"\"WindowsFirewallBackend\"\"\";\r\n" +
            "var character = '\\'';\r\n" +
            "var realReference = new WindowsFirewallBackend();\r\n";

        string sanitized = CSharpSourceSanitizer.StripCommentsAndLiterals(source);

        Assert.Equal(source.Length, sanitized.Length);
        Assert.Equal(source.Count(character => character == '\n'), sanitized.Count(character => character == '\n'));
        Assert.DoesNotContain("WindowsFirewallBackend comment", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("WindowsFirewallRuleLifecycleBackend block", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("\"WindowsFirewallBackend\"", sanitized, StringComparison.Ordinal);
        Assert.Contains("new WindowsFirewallBackend()", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public void ReflectionRule_DetectsConcreteBackendAndWindowsFormsLeaks_InDummyFixtures()
    {
        var backendViolations = ArchitectureBoundaryEvaluator.FindForbiddenTypeReferences(
            targetTypes: [typeof(ViolatingCoordinatorFixture)],
            isForbiddenType: type => type.Name.Equals(
                nameof(DummyWindowsFirewallBackend),
                StringComparison.Ordinal),
            ruleLabel: "ConcreteWindowsBackend");

        string backendViolation = Assert.Single(backendViolations);
        Assert.Contains(nameof(ViolatingCoordinatorFixture), backendViolation, StringComparison.Ordinal);
        Assert.Contains(nameof(DummyWindowsFirewallBackend), backendViolation, StringComparison.Ordinal);

        var winFormsViolations = ArchitectureBoundaryEvaluator.FindForbiddenTypeReferences(
            targetTypes: [typeof(ViolatingViewModelFixture)],
            isForbiddenType: type =>
                (type.Namespace ?? string.Empty).StartsWith(
                    "System.Windows.Forms",
                    StringComparison.Ordinal),
            ruleLabel: "System.Windows.Forms");

        string winFormsViolation = Assert.Single(winFormsViolations);
        Assert.Contains(nameof(ViolatingViewModelFixture), winFormsViolation, StringComparison.Ordinal);
        Assert.Contains(nameof(Form), winFormsViolation, StringComparison.Ordinal);
    }

    private sealed class DummyWindowsFirewallBackend
    {
    }

    private sealed class ViolatingCoordinatorFixture
    {
        public DummyWindowsFirewallBackend Backend { get; } = new();
    }

    private sealed class ViolatingViewModelFixture
    {
        public Form? LeakedFormReference { get; set; }
    }
}
