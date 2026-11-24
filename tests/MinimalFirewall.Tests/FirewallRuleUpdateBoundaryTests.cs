using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleUpdateBoundaryTests
{
    [Fact]
    public void UpdateBackendContract_IsComFree()
    {
        var method = typeof(IFirewallRuleUpdateBackend).GetMethod(nameof(IFirewallRuleUpdateBackend.UpdateRemoteAddresses));

        Assert.NotNull(method);
        Assert.Equal(typeof(FirewallRuleUpdateResult), method!.ReturnType);
    }

    [Fact]
    public void SuccessResult_HasNoErrorMetadata()
    {
        var result = FirewallRuleUpdateResult.Success();

        Assert.True(result.Succeeded);
        Assert.Equal(FirewallRuleUpdateErrorCode.None, result.ErrorCode);
        Assert.Null(result.Error);
        Assert.Null(result.HResult);
    }

    [Fact]
    public void FailureResult_PreservesStructuredCodeAndHResult()
    {
        var hresult = unchecked((int)0x80070005);
        var result = FirewallRuleUpdateResult.Failure(
            FirewallRuleUpdateErrorCode.AccessDenied,
            "access denied",
            hresult);

        Assert.False(result.Succeeded);
        Assert.Equal(FirewallRuleUpdateErrorCode.AccessDenied, result.ErrorCode);
        Assert.Equal("access denied", result.Error);
        Assert.Equal(hresult, result.HResult);
    }

    [Theory]
    [InlineData(unchecked((int)0x80070005), FirewallRuleUpdateErrorCode.AccessDenied)]
    [InlineData(unchecked((int)0x80070002), FirewallRuleUpdateErrorCode.RuleNotFound)]
    [InlineData(unchecked((int)0x80070490), FirewallRuleUpdateErrorCode.RuleNotFound)]
    [InlineData(unchecked((int)0x80004005), FirewallRuleUpdateErrorCode.OperationFailed)]
    public void ErrorMapper_MapsKnownHResultsToDomainCodes(
        int hresult,
        FirewallRuleUpdateErrorCode expected)
    {
        Assert.Equal(expected, FirewallRuleUpdateErrorMapper.FromHResult(hresult));
    }

    [Fact]
    public void FailureResult_RejectsSuccessErrorCode()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            FirewallRuleUpdateResult.Failure(
                FirewallRuleUpdateErrorCode.None,
                "invalid failure"));
    }
}
