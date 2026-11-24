using Xunit;

namespace MinimalFirewall.Tests;

public sealed class RuleTimestampServiceBehaviorTests
{
    [Fact]
    public void EnsureStamped_NewRuleOutsideBaseline_ReturnsAndPersistsProvidedTimestamp()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var stamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        Assert.Equal(stamp, service.EnsureStamped("Demo Rule", stamp));
        service.Flush();

        var reloaded = storage.CreateService();
        Assert.Equal(stamp, reloaded.Get("Demo Rule"));
        Assert.False(reloaded.IsBaselineSession);
    }

    [Fact]
    public void EnsureStamped_ExistingRuleIsStableAndCaseInsensitiveAfterReload()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var firstStamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var laterStamp = firstStamp.AddDays(1);

        service.Set("Demo Rule", firstStamp);
        service.Flush();

        var reloaded = storage.CreateService();

        Assert.Equal(firstStamp, reloaded.EnsureStamped("demo rule", laterStamp));
        Assert.Equal(firstStamp, reloaded.Get("DEMO RULE"));
    }

    [Fact]
    public void EnsureStamped_BaselineStoresUnknownSentinelAndEndsBaselineSession()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var observedAt = DateTime.UtcNow;

        Assert.True(service.IsBaselineSession);
        Assert.Null(service.EnsureStamped("Existing Rule", observedAt, treatAsBaseline: true));

        service.Flush();
        service.EndBaselineSession();

        var reloaded = storage.CreateService();

        Assert.False(reloaded.IsBaselineSession);
        Assert.Null(reloaded.Get("Existing Rule"));
        Assert.Null(reloaded.EnsureStamped("Existing Rule", observedAt.AddDays(1)));
    }

    [Fact]
    public void SetAndFlush_PersistUpdatedTimestamp()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var stamp = new DateTime(2026, 2, 3, 4, 5, 6, DateTimeKind.Utc);

        service.Set("Rule A", stamp);
        service.Flush();

        Assert.Equal(stamp, storage.CreateService().Get("rule a"));
    }

    [Fact]
    public void PruneTo_RemovesInactiveRulesAndPersistsResult()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var stamp = DateTime.UtcNow;

        service.Set("Keep Rule", stamp);
        service.Set("Remove Rule", stamp);
        service.Flush();

        service.PruneTo(["keep rule"]);
        service.Flush();

        var reloaded = storage.CreateService();
        Assert.Equal(stamp, reloaded.Get("KEEP RULE"));
        Assert.Null(reloaded.Get("Remove Rule"));
    }

    [Fact]
    public void Clear_RemovesPersistedTimestamps()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        service.Set("Demo Rule", DateTime.UtcNow);
        service.Flush();

        service.Clear();

        Assert.Null(storage.CreateService().Get("Demo Rule"));
    }

    [Fact]
    public void Load_WhenJsonIsCorrupted_ResetsToEmptyWithoutThrowing()
    {
        using var storage = new TemporaryTimestampStorage();
        File.WriteAllText(storage.FilePath, "{ invalid json");

        var service = storage.CreateService();

        Assert.Null(service.Get("Demo Rule"));
        Assert.False(service.IsBaselineSession);
    }

    [Fact]
    public void EnsureStamped_EmptyNameDoesNotCreatePersistedEntry()
    {
        using var storage = new TemporaryTimestampStorage();
        var service = storage.CreateService();
        var stamp = DateTime.UtcNow;

        Assert.Equal(stamp, service.EnsureStamped(string.Empty, stamp));
        service.Flush();

        Assert.False(File.Exists(storage.FilePath));
    }

    private sealed class TemporaryTimestampStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-timestamp-tests-{Guid.NewGuid():N}");

        public string FilePath => Path.Combine(_directory, "rule_timestamps.json");

        public TemporaryTimestampStorage()
        {
            Directory.CreateDirectory(_directory);
        }

        public RuleTimestampService CreateService() => new(FilePath);

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
