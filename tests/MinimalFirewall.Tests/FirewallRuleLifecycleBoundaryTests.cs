using System.Runtime.CompilerServices;
using System.Reflection;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleLifecycleBoundaryTests
{
    [Fact]
    public void DeleteApplicationRules_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.DeleteApplicationRules(["C:\\Apps\\demo.exe"]);

        Assert.Equal(["C:\\Apps\\demo.exe"], backend.DeletedByPath);
    }

    [Fact]
    public void DeleteUwpRules_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.DeleteUwpRules(["Contoso.App_123"]);

        Assert.Equal(["Contoso.App_123"], backend.DeletedUwp);
    }

    [Fact]
    public void DeleteAdvancedRules_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.DeleteAdvancedRules(["MFW - Demo"]);

        Assert.Equal(["MFW - Demo"], backend.DeletedByName);
    }

    [Fact]
    public void DeleteRulesForWildcard_RoutesDescriptionToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.DeleteRulesForWildcard(new WildcardRule { FolderPath = @"C:\Apps\*" });

        Assert.Equal(["MFW_Wildcard_Path:[C:\\Apps\\*]"], backend.DeletedByDescription);
    }

    [Fact]
    public async Task DeleteGroupAsync_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        await service.DeleteGroupAsync("Demo Group");

        Assert.Equal(["Demo Group"], backend.DeletedByGroup);
    }

    [Fact]
    public void EnableForeignRule_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.EnableForeignRule(CreateForeignRuleChange("Foreign Rule"));

        Assert.Equal(["Foreign Rule"], backend.EnabledByName);
    }

    [Fact]
    public void DisableForeignRule_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.DisableForeignRule(CreateForeignRuleChange("Foreign Rule"));

        Assert.Equal(["Foreign Rule"], backend.DisabledByName);
    }

    [Fact]
    public void AcceptForeignRule_RoutesToLifecycleBackend()
    {
        var backend = new FakeLifecycleBackend();
        var service = CreateService(backend);

        service.AcceptForeignRule(CreateForeignRuleChange("Foreign Rule"));

        Assert.Equal(["Foreign Rule"], backend.EnabledByName);
    }

    [Fact]
    public void LifecycleBackendFailure_DoesNotThrowOrShowMessageBox()
    {
        var backend = new FakeLifecycleBackend { Failure = "simulated lifecycle failure" };
        var service = CreateService(backend);

        service.DeleteApplicationRules(["C:\\Apps\\demo.exe"]);

        Assert.Equal(1, backend.DeleteByPathCalls);
    }

    private static FirewallRuleChange CreateForeignRuleChange(string ruleName)
    {
        var change = (FirewallRuleChange)RuntimeHelpers.GetUninitializedObject(typeof(FirewallRuleChange));
        var ruleProperty = typeof(FirewallRuleChange).GetProperty("Rule", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("FirewallRuleChange.Rule property was not found.");

        var rule = RuntimeHelpers.GetUninitializedObject(ruleProperty.PropertyType);
        var nameProperty = ruleProperty.PropertyType.GetProperty("Name", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Foreign rule Name property was not found.");

        nameProperty.SetValue(rule, ruleName);
        ruleProperty.SetValue(change, rule);
        return change;
    }

    private static FirewallActionsService CreateService(FakeLifecycleBackend backend)
        => new(
            null!,
            new UserActivityLogger(),
            null!,
            null!,
            null!,
            null!,
            null!,
            null,
            null,
            backend);

    private sealed class FakeLifecycleBackend : IFirewallRuleLifecycleBackend
    {
        public List<string> DeletedByPath { get; } = [];
        public List<string> DeletedUwp { get; } = [];
        public List<string> DeletedByName { get; } = [];
        public List<string> DeletedByDescription { get; } = [];
        public List<string> DeletedByGroup { get; } = [];
        public List<string> EnabledByName { get; } = [];
        public List<string> DisabledByName { get; } = [];
        public int DeleteByPathCalls { get; private set; }
        public string? Failure { get; init; }

        public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> items)
        {
            DeleteByPathCalls++;
            DeletedByPath.AddRange(items);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> items)
        {
            DeletedUwp.AddRange(items);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> items)
        {
            DeletedByName.AddRange(items);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DeleteByDescription(string description)
        {
            DeletedByDescription.Add(description);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName)
        {
            DeletedByGroup.Add(groupName);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DeleteAllMfwRules() => Result();

        public FirewallRuleLifecycleOperationResult EnableByName(string ruleName)
        {
            EnabledByName.Add(ruleName);
            return Result();
        }

        public FirewallRuleLifecycleOperationResult DisableByName(string ruleName)
        {
            DisabledByName.Add(ruleName);
            return Result();
        }

        private FirewallRuleLifecycleOperationResult Result() =>
            Failure == null
                ? FirewallRuleLifecycleOperationResult.Success()
                : FirewallRuleLifecycleOperationResult.Failure(Failure);
    }
}
