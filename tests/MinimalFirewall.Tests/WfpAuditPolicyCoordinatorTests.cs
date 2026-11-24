using Xunit;

namespace MinimalFirewall.Tests;

public sealed class WfpAuditPolicyCoordinatorTests
{
    [Fact]
    public void EnableThenRestore_WhenOriginallyDisabled_EnablesThenDisablesAndDeletesState()
    {
        var backend = new FakeBackend(false);
        var store = new InMemoryStateStore();
        var coordinator = CreateCoordinator(backend, store);

        coordinator.EnableWithBaselineTracking();

        Assert.True(backend.Enabled);
        Assert.NotNull(store.State);
        Assert.True(store.State!.Subcategories.All(x => x.ModifiedByApp));

        coordinator.RestoreBaseline();

        Assert.False(backend.Enabled);
        Assert.Null(store.State);
        Assert.Equal(2, backend.SetCalls);
    }

    [Fact]
    public void EnableThenRestore_WhenOriginallyEnabledByGpo_NeverDisablesOrModifiesOs()
    {
        var backend = new FakeBackend(true);
        var store = new InMemoryStateStore();
        var coordinator = CreateCoordinator(backend, store);

        coordinator.EnableWithBaselineTracking();
        coordinator.RestoreBaseline();

        Assert.True(backend.Enabled);
        Assert.Null(store.State);
        Assert.Equal(0, backend.SetCalls);
    }

    [Fact]
    public void AfterCrash_NextStartupPreservesOriginalBaseline_AndSubsequentExitRestoresToDisabled()
    {
        var firstBackend = new FakeBackend(false);
        var store = new InMemoryStateStore();
        CreateCoordinator(firstBackend, store).EnableWithBaselineTracking();

        Assert.True(firstBackend.Enabled);
        Assert.NotNull(store.State);

        // Simulate process death: the durable state survives while the OS remains enabled.
        var secondBackend = new FakeBackend(true);
        var secondCoordinator = CreateCoordinator(secondBackend, store);

        secondCoordinator.EnableWithBaselineTracking();
        Assert.True(secondBackend.Enabled);
        Assert.Equal(1, secondBackend.SetCalls);
        Assert.False(store.State!.Subcategories.Single().WasFailureAuditingEnabledBeforeApp);

        secondCoordinator.RestoreBaseline();

        Assert.False(secondBackend.Enabled);
        Assert.Null(store.State);
    }

    [Fact]
    public void RestoreBaseline_WhenOsDisableFails_KeepsStateFileForNextRetry()
    {
        var backend = new FakeBackend(false) { FailDisable = true };
        var store = new InMemoryStateStore();
        var coordinator = CreateCoordinator(backend, store);

        coordinator.EnableWithBaselineTracking();
        coordinator.RestoreBaseline();

        Assert.NotNull(store.State);
        Assert.True(backend.Enabled);
    }

    private static WfpAuditPolicyCoordinator CreateCoordinator(
        FakeBackend backend,
        InMemoryStateStore store) =>
        new(
            backend,
            store,
            [Guid.NewGuid().ToString("D")]);

    private sealed class FakeBackend : IWfpAuditPolicyBackend
    {
        public FakeBackend(bool enabled) => Enabled = enabled;

        public bool Enabled { get; private set; }
        public int SetCalls { get; private set; }
        public bool FailDisable { get; set; }

        public bool IsFailureAuditingEnabled(string subcategoryGuid) => Enabled;

        public bool SetFailureAuditing(string subcategoryGuid, bool enable)
        {
            SetCalls++;
            if (!enable && FailDisable)
            {
                return false;
            }

            Enabled = enable;
            return true;
        }
    }

    private sealed class InMemoryStateStore : IWfpAuditStateStore
    {
        public WfpAuditRecoveryState? State { get; private set; }

        public WfpAuditRecoveryState? Load() => State;

        public void Save(WfpAuditRecoveryState state) => State = state;

        public void Delete() => State = null;
    }
}
