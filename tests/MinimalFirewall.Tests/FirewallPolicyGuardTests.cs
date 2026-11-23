using NetFwTypeLib;
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
            NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
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
            NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
            backend.LastRequestedAction);
    }

    [Fact]
    public void BackendWriteFailure_MustReportUnsuccessfulToggle()
    {
        var backend = new FakeFirewallBackend(
            FirewallPolicyState.Allow,
            new SetDefaultOutboundActionResult
            {
                RequestedAction = NET_FW_ACTION_.NET_FW_ACTION_BLOCK
            });

        var toggled = FirewallPolicyGuard.TryToggle(backend, out var result);

        Assert.False(toggled);
        Assert.NotNull(result);
        Assert.False(result.Succeeded);
        Assert.Equal(
            NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
            backend.LastRequestedAction);
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

    private sealed class FakeFirewallBackend : IFirewallBackend
    {
        private readonly FirewallPolicyState _state;
        private readonly SetDefaultOutboundActionResult? _result;
        private readonly Exception? _readException;

        public FakeFirewallBackend(
            FirewallPolicyState state,
            SetDefaultOutboundActionResult? result = null,
            Exception? readException = null)
        {
            _state = state;
            _result = result;
            _readException = readException;
        }

        public NET_FW_ACTION_? LastRequestedAction { get; private set; }

        public FirewallPolicyState GetDefaultOutboundState()
        {
            if (_readException != null)
            {
                throw _readException;
            }

            return _state;
        }

        public SetDefaultOutboundActionResult SetDefaultOutboundAction(
            NET_FW_ACTION_ action)
        {
            LastRequestedAction = action;

            return _result ?? new SetDefaultOutboundActionResult
            {
                RequestedAction = action,
                Profiles =
                [
                    new ProfileActionResult
                    {
                        Profile = NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
                        Succeeded = true
                    }
                ]
            };
        }
    }
}
