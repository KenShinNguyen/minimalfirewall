using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallActionsServiceLockdownTests
{
    [Fact]
    public void ToggleLockdown_HappyPath_RoutesPolicyAndCompletesTransition()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Allow);
        var service = new TestableFirewallActionsService(backend);

        service.ToggleLockdown();

        Assert.Equal(1, service.PrepareCalls);
        Assert.Equal(1, service.VerifyCalls);
        Assert.Equal(1, service.CompleteCalls);
        Assert.True(service.LastPreparedState);
        Assert.True(service.LastCompletedState);
        Assert.Equal(FirewallOutboundAction.Block, backend.LastRequestedAction);
    }

    [Fact]
    public void ToggleLockdown_Failures_FailClosedBeforeAndAfterPreparation()
    {
        var readFailureBackend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            readException: new InvalidOperationException("backend read failed"));
        var readFailureService = new TestableFirewallActionsService(readFailureBackend);

        readFailureService.ToggleLockdown();

        Assert.Equal(0, readFailureService.PrepareCalls);
        Assert.Equal(0, readFailureService.VerifyCalls);
        Assert.Equal(0, readFailureService.CompleteCalls);

        var writeFailureBackend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            writeException: new InvalidOperationException("backend write failed"));
        var writeFailureService = new TestableFirewallActionsService(writeFailureBackend);

        writeFailureService.ToggleLockdown();

        Assert.Equal(1, writeFailureService.PrepareCalls);
        Assert.Equal(1, writeFailureService.VerifyCalls);
        Assert.Equal(0, writeFailureService.CompleteCalls);
        Assert.Equal(FirewallOutboundAction.Block, writeFailureBackend.LastRequestedAction);
    }

    private sealed class TestableFirewallActionsService : FirewallActionsService
    {
        public TestableFirewallActionsService(IFirewallBackend backend)
            : base(
                null!,
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
        public int VerifyCalls { get; private set; }
        public int CompleteCalls { get; private set; }
        public bool LastPreparedState { get; private set; }
        public bool LastCompletedState { get; private set; }

        protected override void PrepareLockdownPrerequisites(bool enableLockdown)
        {
            PrepareCalls++;
            LastPreparedState = enableLockdown;
        }

        protected override bool VerifyLockdownAuditPolicy()
        {
            VerifyCalls++;
            return true;
        }

        protected override void CompleteLockdownTransition(bool lockdownEnabled)
        {
            CompleteCalls++;
            LastCompletedState = lockdownEnabled;
        }
    }

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
