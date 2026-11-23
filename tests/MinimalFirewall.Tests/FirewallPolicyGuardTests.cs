using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallPolicyGuardTests
{
    [Fact]
    public void UnknownState_MustRefuseToggle()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Unknown);

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.Null(result);
        Assert.Null(backend.LastRequestedAction);
    }

    [Fact]
    public void AllowState_TogglesToBlock()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Allow);

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.True(toggled);
        Assert.NotNull(result);
        Assert.Equal(
            FirewallOutboundAction.Block,
            backend.LastRequestedAction);
    }

    [Fact]
    public void BlockState_TogglesToAllow()
    {
        var backend = new FakeFirewallBackend(FirewallPolicyState.Block);

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.True(toggled);
        Assert.NotNull(result);
        Assert.Equal(
            FirewallOutboundAction.Allow,
            backend.LastRequestedAction);
    }

    [Fact]
    public void BackendWriteFailure_MustReportUnsuccessfulToggle()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            new FirewallPolicyOperationResult
            {
                RequestedAction = FirewallOutboundAction.Block
            });

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.NotNull(result);
        Assert.False(result.Succeeded);
        Assert.Equal(FirewallOutboundAction.Block, backend.LastRequestedAction);
    }

    [Fact]
    public void BackendWriteException_MustFailClosed()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            writeException: new InvalidOperationException("backend write failed"));

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.Null(result);
        Assert.Equal(FirewallOutboundAction.Block, backend.LastRequestedAction);
    }

    [Fact]
    public void BackendWriteNullResult_MustFailClosed()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            returnNullResult: true);

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.Null(result);
        Assert.Equal(FirewallOutboundAction.Block, backend.LastRequestedAction);
    }

    [Fact]
    public void BackendReadFailure_MustFailClosed()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            readException: new InvalidOperationException("backend unavailable"));

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.Null(result);
        Assert.Null(backend.LastRequestedAction);
    }

    [Fact]
    public void NullBackend_MustThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => FirewallPolicyGuard.TryToggle(null!, out var result));
    }

    private sealed class FakeFirewallBackend : IFirewallBackend
    {
        private readonly FirewallPolicyState _state;
        private readonly FirewallPolicyOperationResult? _result;
        private readonly Exception? _readException;
        private readonly Exception? _writeException;
        private readonly bool _returnNullResult;

        public FakeFirewallBackend(
            FirewallPolicyState state,
            FirewallPolicyOperationResult? result = null,
            Exception? readException = null,
            Exception? writeException = null,
            bool returnNullResult = false)
        {
            _state = state;
            _result = result;
            _readException = readException;
            _writeException = writeException;
            _returnNullResult = returnNullResult;
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

            if (_returnNullResult)
            {
                return null!;
            }

            return _result ?? new FirewallPolicyOperationResult
            {
                RequestedAction = action,
                Succeeded = true
            };
        }
    }
}
