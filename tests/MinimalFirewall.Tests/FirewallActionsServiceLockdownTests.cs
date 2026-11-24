using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallActionsServiceLockdownTests
{
    [Fact]
    public void ToggleLockdown_HappyPath_EnablesAuditBeforePolicyAndCompletesTransition()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Allow);
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(1, service.PrepareCalls);
        Assert.Equal(1, service.AuditEnableCalls);
        Assert.Equal(1, service.VerifyCalls);
        Assert.Equal(1, service.CompleteCalls);
        Assert.Equal(0, service.AuditRestoreCalls);
        Assert.True(service.LastPreparedState);
        Assert.True(service.LastCompletedState);
        Assert.Empty(service.LockdownMessages);
        Assert.Equal(FirewallOutboundAction.Block, backend.LastRequestedAction);
    }

    [Fact]
    public void ToggleLockdown_FailedAuditVerification_RestoresAuditPolicyAfterFirewallRollback()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Allow);
        var service = new TestableFirewallActionsService(backend)
        {
            AuditPolicyVerifies = false
        };

        service.ToggleLockdown();

        Assert.Equal(1, service.AuditEnableCalls);
        Assert.Equal(1, service.VerifyCalls);
        Assert.Equal(1, service.AuditRestoreCalls);
        Assert.Equal(0, service.CompleteCalls);
        Assert.Single(service.LockdownMessages);
        Assert.Equal("Lockdown Mode Failed", service.LockdownMessages[0].Caption);
    }

    [Fact]
    public void ToggleLockdown_FailedFirewallApply_RestoresAuditWhenRollbackIsComplete()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            writeException: new InvalidOperationException("backend write failed"));
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(1, service.AuditEnableCalls);
        Assert.Equal(1, service.VerifyCalls);
        Assert.Equal(1, service.AuditRestoreCalls);
        Assert.Equal(0, service.CompleteCalls);
        Assert.Single(service.LockdownMessages);
        Assert.Equal("Lockdown Error", service.LockdownMessages[0].Caption);
        Assert.Contains("default outbound policy", service.LockdownMessages[0].Text);
    }

    [Fact]
    public void ToggleLockdown_UnlockApplyFailure_DoesNotRestoreAuditWhileFirewallMayRemainLocked()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Block,
            writeException: new InvalidOperationException("backend write failed"));
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(0, service.AuditEnableCalls);
        Assert.Equal(0, service.VerifyCalls);
        Assert.Equal(0, service.AuditRestoreCalls);
        Assert.Equal(0, service.CompleteCalls);
        Assert.Equal(FirewallOutboundAction.Allow, backend.LastRequestedAction);
    }

    [Fact]
    public void ToggleLockdown_SuccessfulUnlock_RestoresAuditOnlyAfterFirewallTransition()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Block);
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(0, service.AuditEnableCalls);
        Assert.Equal(0, service.VerifyCalls);
        Assert.Equal(1, service.CompleteCalls);
        Assert.Equal(1, service.AuditRestoreCalls);
        Assert.False(service.LastCompletedState);
        Assert.Equal(FirewallOutboundAction.Allow, backend.LastRequestedAction);
    }

    [Fact]
    public void ToggleLockdown_ReadFailureDoesNotTouchAuditPolicy()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            readException: new InvalidOperationException("backend read failed"));
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(0, service.PrepareCalls);
        Assert.Equal(0, service.AuditEnableCalls);
        Assert.Equal(0, service.VerifyCalls);
        Assert.Equal(0, service.AuditRestoreCalls);
        Assert.Equal(0, service.CompleteCalls);
        Assert.Single(service.LockdownMessages);
        Assert.Equal("Firewall State Unknown", service.LockdownMessages[0].Caption);
    }

    private sealed class TestableFirewallActionsService : FirewallActionsService
    {
        public TestableFirewallActionsService(IFirewallBackend backend)
            : base(
                new UserActivityLogger(),
                null!,
                null!,
                null!,
                null!,
                null!,
                backend)
        {
        }

        public int PrepareCalls { get; private set; }
        public int AuditEnableCalls { get; private set; }
        public int AuditRestoreCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public int CompleteCalls { get; private set; }
        public bool LastPreparedState { get; private set; }
        public bool LastCompletedState { get; private set; }
        public bool AuditPolicyVerifies { get; set; } = true;

        public List<LockdownMessage> LockdownMessages { get; } = [];

        protected override void PrepareLockdownPrerequisites(bool enableLockdown)
        {
            PrepareCalls++;
            LastPreparedState = enableLockdown;
        }

        protected override void EnableLockdownAuditPolicy()
        {
            AuditEnableCalls++;
        }

        protected override void RestoreLockdownAuditPolicy()
        {
            AuditRestoreCalls++;
        }

        protected override bool VerifyLockdownAuditPolicy()
        {
            VerifyCalls++;
            return AuditPolicyVerifies;
        }

        protected override void CompleteLockdownTransition(bool lockdownEnabled)
        {
            CompleteCalls++;
            LastCompletedState = lockdownEnabled;
            if (!lockdownEnabled)
            {
                RestoreLockdownAuditPolicy();
            }
        }

        protected override void ShowLockdownMessage(string text, string caption)
        {
            LockdownMessages.Add(new LockdownMessage(text, caption));
        }
    }

    private sealed record LockdownMessage(string Text, string Caption);

    private sealed class FakeFirewallBackend : IFirewallBackend
    {
        private readonly FirewallPolicyState _state;
        private readonly Exception? _readException;
        private readonly Exception? _writeException;

        public FakeFirewallBackend(
            FirewallPolicyState state,
            Exception? readException = null,
            Exception? writeException = null)
        {
            _state = state;
            _readException = readException;
            _writeException = writeException;
        }

        public FirewallOutboundAction? LastRequestedAction { get; private set; }

        public FirewallPolicyState GetDefaultOutboundState()
        {
            if (_readException != null)
            {
                throw _readException;
            }

            return _state;
        }

        public FirewallPolicyOperationResult SetDefaultOutboundAction(
            FirewallOutboundAction action)
        {
            LastRequestedAction = action;

            if (_writeException != null)
            {
                throw _writeException;
            }

            return new FirewallPolicyOperationResult
            {
                RequestedAction = action,
                Succeeded = true
            };
        }
    }
}
