using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using MinimalFirewall;
using Xunit;

namespace MinimalFirewall.Tests.Architecture;

public sealed class ArchitectureBoundaryTests
{
    private static readonly Assembly AppAssembly = typeof(MainForm).Assembly;

    private static readonly HashSet<string> NoAllowedFiles = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> WindowsBackendFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "WindowsFirewallBackend.cs",
        "WindowsFirewallPolicyAdminBackend.cs",
        "WindowsFirewallRuleCreationBackend.cs",
        "WindowsFirewallRuleGroupBackend.cs",
        "WindowsFirewallRuleLifecycleBackend.cs",
        "WindowsFirewallRuleObservationBackend.cs",
        "WindowsFirewallRuleQueryBackend.cs",
        "WindowsFirewallRuleUpdateBackend.cs",
        "WindowsSystemFirewallRuleBackend.cs"
    };

    private static readonly string[] ConcreteWindowsBackends =
    [
        "WindowsFirewallBackend",
        "WindowsFirewallPolicyAdminBackend",
        "WindowsFirewallRuleCreationBackend",
        "WindowsFirewallRuleGroupBackend",
        "WindowsFirewallRuleLifecycleBackend",
        "WindowsFirewallRuleObservationBackend",
        "WindowsFirewallRuleQueryBackend",
        "WindowsFirewallRuleUpdateBackend",
        "WindowsSystemFirewallRuleBackend"
    ];

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ScopedMethodExceptions =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["MainForm.cs"] = ["InitializeServices"],
            ["Program.cs"] = ["DescribeLockdownState"]
        };

    // Existing constructor defaults are the compatibility composition seams in these
    // two files. Mask only the known initializer declarations, not the full files.
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ScopedLineExceptions =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["MainViewModel.cs"] =
            [
                @"^\s*private\s+static\s+readonly\s+IFirewallBackend\s+_policyBackend\s*=\s*new\s+WindowsFirewallBackend\s*\(\s*\)\s*;\s*$"
            ],
            ["FirewallActionService.cs"] =
            [
                @"^\s*private\s+readonly\s+IFirewallBackend\s+_policyBackend\s*=.*new\s+WindowsFirewallBackend\s*\(\s*\)\s*;\s*$",
                @"^\s*private\s+readonly\s+ISystemFirewallRuleBackend\s+_systemRuleBackend\s*=.*new\s+WindowsSystemFirewallRuleBackend\s*\(\s*\)\s*;\s*$",
                @"^\s*private\s+readonly\s+IFirewallRuleLifecycleBackend\s+_ruleLifecycleBackend\s*=.*new\s+WindowsFirewallRuleLifecycleBackend\s*\(\s*\)\s*;\s*$",
                @"^\s*private\s+readonly\s+IFirewallRuleQueryBackend\s+_ruleQueryBackend\s*=.*new\s+WindowsFirewallRuleQueryBackend\s*\(\s*\)\s*;\s*$",
                @"^\s*private\s+readonly\s+IFirewallRuleCreationBackend\s+_ruleCreationBackend\s*=.*new\s+WindowsFirewallRuleCreationBackend\s*\(\s*\)\s*;\s*$",
                @"^\s*private\s+readonly\s+RuleMutationCoordinator\s+_ruleMutationCoordinator\s*=.*new\s+WindowsFirewallRuleCreationBackend\s*\(\s*\).*;\s*$"
            ]
        };

    private static readonly IReadOnlyDictionary<Type, IReadOnlySet<string>> LegacyWinFormsMemberExceptions =
        new Dictionary<Type, IReadOnlySet<string>>
        {
            // Existing UI message-box bridge is retained in the service during this
            // zero-production-change gate. Other declared member contracts remain checked.
            [typeof(FirewallActionsService)] = new HashSet<string>(StringComparer.Ordinal)
            {
                "SafeShowMessageBox"
            }
        };

    [Fact]
    public void ComOwnership_RemainsRestrictedToWindowsBackendSources()
    {
        IReadOnlyList<SourceDocument> documents = LoadProductionSourceDocuments();

        var forbiddenEverywhere = ArchitectureBoundaryEvaluator.FindForbiddenSourceTokens(
            documents,
            forbiddenIdentifiers: ["FirewallRuleHandle", "FirewallRuleService"],
            allowedFileNames: NoAllowedFiles);

        var comLeaks = ArchitectureBoundaryEvaluator.FindForbiddenSourceTokens(
            documents,
            forbiddenIdentifiers:
            [
                "NetFwTypeLib",
                "HNetCfg",
                "INetFw",
                "NET_FW_",
                "Marshal.ReleaseComObject"
            ],
            allowedFileNames: WindowsBackendFiles);

        var violations = forbiddenEverywhere.Concat(comLeaks).ToArray();
        if (violations.Length > 0)
        {
            Assert.Fail(
                "Architecture boundary violations found for COM ownership:\n - " +
                string.Join("\n - ", violations));
        }
    }

    [Fact]
    public void ConcreteWindowsBackends_MustRemainBehindBackendAndCompositionBoundaries()
    {
        IReadOnlyList<SourceDocument> documents = LoadProductionSourceDocuments();

        var violations = ArchitectureBoundaryEvaluator.FindForbiddenSourceTokens(
            documents,
            forbiddenIdentifiers: ConcreteWindowsBackends,
            allowedFileNames: WindowsBackendFiles,
            scopedMethodExceptions: ScopedMethodExceptions,
            scopedLineExceptions: ScopedLineExceptions);

        if (violations.Count > 0)
        {
            Assert.Fail(
                "Concrete Windows backend references escaped their approved backend/composition seams:\n - " +
                string.Join("\n - ", violations));
        }
    }

    [Fact]
    public void ViewModels_Coordinators_AndUiControls_MustNotExposeConcreteWindowsBackendTypes()
    {
        Type[] targetTypes = AppAssembly.GetTypes()
            .Where(type =>
                type.Name.EndsWith("ViewModel", StringComparison.Ordinal) ||
                type.Name.EndsWith("Coordinator", StringComparison.Ordinal) ||
                (typeof(Control).IsAssignableFrom(type) && type != typeof(MainForm)))
            .ToArray();

        Assert.NotEmpty(targetTypes);

        var forbiddenNames = new HashSet<string>(ConcreteWindowsBackends, StringComparer.Ordinal);
        var violations = ArchitectureBoundaryEvaluator.FindForbiddenTypeReferences(
            targetTypes,
            isForbiddenType: type => forbiddenNames.Contains(type.Name),
            ruleLabel: "ConcreteWindowsBackend");

        if (violations.Count > 0)
        {
            Assert.Fail(
                "A ViewModel, coordinator, or UI control exposes a concrete Windows backend type:\n - " +
                string.Join("\n - ", violations));
        }
    }

    [Fact]
    public void ViewModels_AndLogicCoordinators_MustNotExposeWindowsFormsTypes()
    {
        Type[] targetTypes = AppAssembly.GetTypes()
            .Where(type =>
                type.Name.EndsWith("ViewModel", StringComparison.Ordinal) ||
                type.Name.EndsWith("Coordinator", StringComparison.Ordinal) ||
                type == typeof(FirewallActionsService))
            .ToArray();

        Assert.NotEmpty(targetTypes);

        var violations = ArchitectureBoundaryEvaluator.FindForbiddenTypeReferences(
            targetTypes,
            isForbiddenType: type =>
                (type.Namespace ?? string.Empty).StartsWith(
                    "System.Windows.Forms",
                    StringComparison.Ordinal),
            ruleLabel: "System.Windows.Forms",
            ignoredMembersByType: LegacyWinFormsMemberExceptions);

        if (violations.Count > 0)
        {
            Assert.Fail(
                "A ViewModel or logic coordinator exposes a Windows Forms type in its member contract:\n - " +
                string.Join("\n - ", violations));
        }
    }

    private static IReadOnlyList<SourceDocument> LoadProductionSourceDocuments()
    {
        string repoRoot = LocateRepoRoot();
        string sourceRoot = Path.Combine(repoRoot, "src");

        return Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path =>
                !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
                !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
                !path.EndsWith(".Designer.cs", StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(path => new SourceDocument(Path.GetFileName(path), File.ReadAllText(path)))
            .ToArray();
    }

    private static string LocateRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) ||
                Directory.EnumerateFiles(directory.FullName, "*.sln", SearchOption.TopDirectoryOnly).Any())
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"Could not locate repository root from '{AppContext.BaseDirectory}'.");
    }
}
