using Xunit;

namespace MinimalFirewall.Tests;

public sealed class WfpAuditPolicyLeaseTests
{
    private const uint Success = 0x1;
    private const uint Failure = 0x2;
    private const uint None = 0x4;

    [Fact]
    public void Enable_PreservesOriginalSuccessWhereRequired_AndEnablesFailure()
    {
        var store = new FakeAuditPolicyStore(
            packetDrop: Success,
            connection: Success | Failure);
        var lease = store.CreateLease();

        lease.Enable();

        Assert.Equal(Success | Failure, store.PacketDropPolicy);
        Assert.Equal(Failure, store.ConnectionPolicy);
        Assert.True(lease.IsActive);

        lease.Restore();

        Assert.Equal(Success, store.PacketDropPolicy);
        Assert.Equal(Success | Failure, store.ConnectionPolicy);
        Assert.False(lease.IsActive);
    }

    [Fact]
    public void Enable_ReplacesNoneSentinelWithFailureOnly_AndRestoreReturnsNone()
    {
        var store = new FakeAuditPolicyStore(packetDrop: None, connection: None);
        var lease = store.CreateLease();

        lease.Enable();

        Assert.Equal(Failure, store.PacketDropPolicy);
        Assert.Equal(Failure, store.ConnectionPolicy);

        lease.Restore();

        Assert.Equal(None, store.PacketDropPolicy);
        Assert.Equal(None, store.ConnectionPolicy);
    }

    [Fact]
    public void Enable_IsIdempotent_AndDoesNotReplaceOriginalSnapshot()
    {
        var store = new FakeAuditPolicyStore(packetDrop: Success, connection: Success | Failure);
        var lease = store.CreateLease();

        lease.Enable();
        store.SetPolicies(packetDrop: 0, connection: 0);
        lease.Enable();

        Assert.Equal(2, store.ReadCount);
        Assert.Equal(2, store.WriteCount);
        Assert.Equal(Success | Failure, store.PacketDropPolicy);
        Assert.Equal(Failure, store.ConnectionPolicy);

        lease.Restore();

        Assert.Equal(Success, store.PacketDropPolicy);
        Assert.Equal(Success | Failure, store.ConnectionPolicy);
    }

    [Fact]
    public void Enable_WhenSnapshotReadFails_DoesNotPublishPartialSnapshotOrWrite()
    {
        var store = new FakeAuditPolicyStore(packetDrop: Success, connection: Failure)
        {
            FailReadFor = WfpAuditPolicyLease.ConnectionSubcategory
        };
        var lease = store.CreateLease();

        Assert.Throws<InvalidOperationException>(() => lease.Enable());

        Assert.False(lease.IsActive);
        Assert.Equal(0, store.WriteCount);

        store.FailReadFor = null;
        lease.Enable();

        Assert.True(lease.IsActive);
        Assert.Equal(1, store.WriteCount);
    }

    [Fact]
    public void Restore_WhenWriteFails_RetainsSnapshotForRetry()
    {
        var store = new FakeAuditPolicyStore(packetDrop: Success, connection: Success | Failure);
        var lease = store.CreateLease();
        lease.Enable();

        store.FailNextWrite = true;

        Assert.Throws<InvalidOperationException>(() => lease.Restore());
        Assert.True(lease.IsActive);

        lease.Restore();

        Assert.False(lease.IsActive);
        Assert.Equal(Success, store.PacketDropPolicy);
        Assert.Equal(Success | Failure, store.ConnectionPolicy);
    }

    [Fact]
    public void Restore_WithoutActiveLease_DoesNotReadOrWritePolicy()
    {
        var store = new FakeAuditPolicyStore(packetDrop: Success, connection: Failure);
        var lease = store.CreateLease();

        lease.Restore();

        Assert.Equal(0, store.ReadCount);
        Assert.Equal(0, store.WriteCount);
        Assert.Equal(Success, store.PacketDropPolicy);
        Assert.Equal(Failure, store.ConnectionPolicy);
    }

    private sealed class FakeAuditPolicyStore
    {
        private readonly Dictionary<Guid, uint> _policies = new();

        public FakeAuditPolicyStore(uint packetDrop, uint connection)
        {
            _policies[WfpAuditPolicyLease.PacketDropSubcategory] = packetDrop;
            _policies[WfpAuditPolicyLease.ConnectionSubcategory] = connection;
        }

        public int ReadCount { get; private set; }
        public int WriteCount { get; private set; }
        public Guid? FailReadFor { get; set; }
        public bool FailNextWrite { get; set; }

        public uint PacketDropPolicy => _policies[WfpAuditPolicyLease.PacketDropSubcategory];
        public uint ConnectionPolicy => _policies[WfpAuditPolicyLease.ConnectionSubcategory];

        public WfpAuditPolicyLease CreateLease() =>
            new(Read, Write);

        public void SetPolicies(uint packetDrop, uint connection)
        {
            _policies[WfpAuditPolicyLease.PacketDropSubcategory] = packetDrop;
            _policies[WfpAuditPolicyLease.ConnectionSubcategory] = connection;
        }

        private uint Read(Guid subcategory)
        {
            ReadCount++;
            if (FailReadFor == subcategory)
            {
                throw new InvalidOperationException("Simulated audit policy query failure.");
            }

            return _policies[subcategory];
        }

        private void Write(IReadOnlyList<AuditPolicySetting> settings)
        {
            WriteCount++;
            if (FailNextWrite)
            {
                FailNextWrite = false;
                throw new InvalidOperationException("Simulated audit policy write failure.");
            }

            foreach (AuditPolicySetting setting in settings)
            {
                _policies[setting.SubcategoryId] = setting.AuditingInformation;
            }
        }
    }
}
