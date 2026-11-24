using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallSnapshotServiceBehaviorTests
{
    [Fact]
    public void LoadSnapshot_WhenFileDoesNotExist_ReturnsEmptyCaseInsensitiveSet()
    {
        using var storage = new TemporarySnapshotStorage();
        var service = storage.CreateService();

        var snapshot = service.LoadSnapshot();

        Assert.Empty(snapshot);
        Assert.False(service.SnapshotExists());

        snapshot.Add("Rule A");
        Assert.Contains("RULE A", snapshot);
    }

    [Fact]
    public void SaveSnapshot_DeduplicatesNamesCaseInsensitively_AndReloadPreservesComparer()
    {
        using var storage = new TemporarySnapshotStorage();
        var service = storage.CreateService();

        service.SaveSnapshot(["Demo Rule", "demo rule", "Other Rule"]);
        var reloaded = storage.CreateService();
        var snapshot = reloaded.LoadSnapshot();

        Assert.Equal(2, snapshot.Count);
        Assert.Contains("DEMO RULE", snapshot);
        Assert.Contains("other RULE", snapshot);
        Assert.True(reloaded.SnapshotExists());
    }

    [Fact]
    public void DeleteSnapshot_RemovesPersistedFile()
    {
        using var storage = new TemporarySnapshotStorage();
        var service = storage.CreateService();
        service.SaveSnapshot(["Demo Rule"]);

        service.DeleteSnapshot();

        Assert.False(service.SnapshotExists());
        Assert.Empty(service.LoadSnapshot());
    }

    [Fact]
    public void LoadSnapshot_WhenJsonIsCorrupted_ReturnsEmptySetWithoutThrowing()
    {
        using var storage = new TemporarySnapshotStorage();
        File.WriteAllText(storage.FilePath, "{ invalid json");

        var service = storage.CreateService();

        Assert.Empty(service.LoadSnapshot());
    }

    [Fact]
    public void LoadSnapshot_WhenJsonIsNull_ReturnsEmptyCaseInsensitiveSet()
    {
        using var storage = new TemporarySnapshotStorage();
        File.WriteAllText(storage.FilePath, "null");

        var service = storage.CreateService();
        var snapshot = service.LoadSnapshot();

        Assert.Empty(snapshot);

        snapshot.Add("Any Rule");
        Assert.Contains("ANY RULE", snapshot);
    }

    private sealed class TemporarySnapshotStorage : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            $"mfw-snapshot-tests-{Guid.NewGuid():N}");

        public string FilePath => Path.Combine(_directory, "known_state.json");

        public TemporarySnapshotStorage()
        {
            Directory.CreateDirectory(_directory);
        }

        public FirewallSnapshotService CreateService() => new(FilePath);

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
