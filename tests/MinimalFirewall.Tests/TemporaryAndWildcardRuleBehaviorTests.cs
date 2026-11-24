using Xunit;

namespace MinimalFirewall.Tests;

public sealed class TemporaryAndWildcardRuleBehaviorTests
{
    [Fact]
    public void TemporaryRuleManager_AddPersistsAndReloadsRule()
    {
        using var storage = new TemporaryRuleTestStorage();
        var expiry = DateTime.UtcNow.AddMinutes(-1);

        using (var manager = storage.CreateManager())
        {
            manager.Add("Demo Rule", expiry);
        }

        using var reloaded = storage.CreateManager();

        var expired = reloaded.GetExpiredRules();
        Assert.Equal(expiry, expired["Demo Rule"]);
    }

    [Fact]
    public void TemporaryRuleManager_GetExpiredRulesReturnsOnlyExpiredRules()
    {
        using var storage = new TemporaryRuleTestStorage();
        using var manager = storage.CreateManager();

        manager.Add("Expired", DateTime.UtcNow.AddMinutes(-1));
        manager.Add("Active", DateTime.UtcNow.AddMinutes(10));

        var expired = manager.GetExpiredRules();

        Assert.True(expired.ContainsKey("Expired"));
        Assert.False(expired.ContainsKey("Active"));
    }

    [Fact]
    public void TemporaryRuleManager_RemovePersistsDeletion()
    {
        using var storage = new TemporaryRuleTestStorage();
        using (var manager = storage.CreateManager())
        {
            manager.Add("Demo Rule", DateTime.UtcNow.AddHours(1));
            manager.Remove("demo rule");
        }

        using var reloaded = storage.CreateManager();
        Assert.Empty(reloaded.GetExpiredRules());
    }

    [Fact]
    public void TemporaryRuleManager_RuleNamesAreCaseInsensitive()
    {
        using var storage = new TemporaryRuleTestStorage();
        using var manager = storage.CreateManager();

        manager.Add("Demo Rule", DateTime.UtcNow.AddMinutes(-1));
        manager.Add("demo rule", DateTime.UtcNow.AddMinutes(-2));

        var expired = manager.GetExpiredRules();

        Assert.Single(expired);
        Assert.Equal(DateTime.UtcNow.AddMinutes(-2), expired["DEMO RULE"], TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void WildcardRuleService_AddDuplicateIsIgnored()
    {
        using var storage = new WildcardRuleTestStorage();
        using var service = storage.CreateService();

        service.AddRule(Rule(@"C:\Apps", "*.exe", "Block"));
        service.AddRule(Rule(@"c:\apps", "*.EXE", "Allow"));

        var rules = service.GetRules();

        Assert.Single(rules);
        Assert.Equal("Block", rules[0].Action);
    }

    [Fact]
    public void WildcardRuleService_MatchSupportsFolderAndExeWildcardsCaseInsensitively()
    {
        using var storage = new WildcardRuleTestStorage();
        using var service = storage.CreateService();

        var rule = Rule(@"C:\Apps\*", "client-?.exe", "Block");
        service.AddRule(rule);

        Assert.Same(rule, service.Match(@"c:\apps\Tools\CLIENT-1.EXE"));
        Assert.Null(service.Match(@"c:\apps\Tools\CLIENT-12.EXE"));
        Assert.Null(service.Match(@"c:\other\CLIENT-1.EXE"));
    }

    [Fact]
    public void WildcardRuleService_RemoveRuleInvalidatesMatchAndPersists()
    {
        using var storage = new WildcardRuleTestStorage();
        var rule = Rule(@"C:\Apps", "*.exe", "Block");

        using (var service = storage.CreateService())
        {
            service.AddRule(rule);
            Assert.NotNull(service.Match(@"C:\Apps\demo.exe"));
            service.RemoveRule(rule);
            Assert.Null(service.Match(@"C:\Apps\demo.exe"));
        }

        using var reloaded = storage.CreateService();
        Assert.Empty(reloaded.GetRules());
    }

    [Fact]
    public void WildcardRuleService_ClearRulesRemovesAllRules()
    {
        using var storage = new WildcardRuleTestStorage();
        using var service = storage.CreateService();

        service.AddRule(Rule(@"C:\Apps", "*.exe", "Block"));
        service.AddRule(Rule(@"C:\Tools", "*.dll", "Allow"));

        service.ClearRules();

        Assert.Empty(service.GetRules());
        Assert.Null(service.Match(@"C:\Apps\demo.exe"));
        Assert.Null(service.Match(@"C:\Tools\demo.dll"));
    }

    private static WildcardRule Rule(string folderPath, string exeName, string action)
        => new()
        {
            FolderPath = folderPath,
            ExeName = exeName,
            Action = action
        };

    private sealed class TemporaryRuleTestStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-temp-rule-tests-{Guid.NewGuid():N}");

        public TemporaryRuleManager CreateManager()
        {
            Directory.CreateDirectory(_directory);
            return new TemporaryRuleManager(Path.Combine(_directory, "temporary_rules.json"));
        }

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }

    private sealed class WildcardRuleTestStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-wildcard-tests-{Guid.NewGuid():N}");

        public WildcardRuleService CreateService()
        {
            Directory.CreateDirectory(_directory);
            return new WildcardRuleService(Path.Combine(_directory, "wildcard_rules.json"));
        }

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
