using System;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallPolicyAdminBoundaryTests
{
    [Fact]
    public void ResetFirewall_RoutesToBackend()
    {
        var backend = new RecordingPolicyAdminBackend
        {
            Result = FirewallPolicyAdminResult.Success()
        };

        AdminTaskService.ResetFirewall(backend);

        Assert.Equal(1, backend.ResetCalls);
    }

    [Fact]
    public void ResetFirewall_DoesNotThrowWhenBackendFails()
    {
        var exception = new COMException(
            "access denied",
            unchecked((int)0x80070005));

        var backend = new RecordingPolicyAdminBackend
        {
            Result = FirewallPolicyAdminResult.Failure(
                "Windows Firewall reset was denied.",
                exception)
        };

        var exceptionFromCall = Record.Exception(() => AdminTaskService.ResetFirewall(backend));

        Assert.Null(exceptionFromCall);
        Assert.Equal(1, backend.ResetCalls);
        Assert.False(backend.Result.Succeeded);
        Assert.Equal(exception.HResult, backend.Result.HResult);
        Assert.Same(exception, backend.Result.Exception);
    }

    [Fact]
    public void PolicyAdminFailureResult_PreservesHResultAndException()
    {
        var exception = new COMException(
            "restore failed",
            unchecked((int)0x80070005));

        var result = FirewallPolicyAdminResult.Failure(
            "Windows Firewall reset failed.",
            exception);

        Assert.False(result.Succeeded);
        Assert.Equal("Windows Firewall reset failed.", result.Error);
        Assert.Equal(exception.HResult, result.HResult);
        Assert.Same(exception, result.Exception);
    }

    private sealed class RecordingPolicyAdminBackend : IFirewallPolicyAdminBackend
    {
        public FirewallPolicyAdminResult Result { get; init; } =
            FirewallPolicyAdminResult.Success();

        public int ResetCalls { get; private set; }

        public FirewallPolicyAdminResult ResetFirewall()
        {
            ResetCalls++;
            return Result;
        }
    }
}
