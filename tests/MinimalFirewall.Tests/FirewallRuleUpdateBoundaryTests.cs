using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleUpdateBoundaryTests
{
    [Fact]
    public void UpdateBackendContract_IsComFreeAndDoesNotExposeExceptions()
    {
        var method = typeof(IFirewallRuleUpdateBackend).GetMethod(nameof(IFirewallRuleUpdateBackend.UpdateRemoteAddresses));

        Assert.NotNull(method);
        Assert.Equal(typeof(FirewallRuleUpdateResult), method!.ReturnType);
        Assert.All(method.GetParameters(), parameter =>
            Assert.Equal(typeof(string), parameter.ParameterType));
        Assert.DoesNotContain(
            typeof(FirewallRuleUpdateResult).GetProperties(),
            property => typeof(Exception).IsAssignableFrom(property.PropertyType));
        Assert.DoesNotContain(
            typeof(FirewallRuleUpdateResult).GetProperties(),
            property => property.PropertyType.Namespace?.StartsWith("NetFwTypeLib", StringComparison.Ordinal) == true);
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
    [InlineData(unchecked((int)0x800706D9), FirewallRuleUpdateErrorCode.FirewallUnavailable)]
    [InlineData(unchecked((int)0x80070002), FirewallRuleUpdateErrorCode.RuleNotFound)]
    [InlineData(unchecked((int)0x80070490), FirewallRuleUpdateErrorCode.RuleNotFound)]
    [InlineData(unchecked((int)0x80004005), FirewallRuleUpdateErrorCode.OperationFailed)]
    public void ErrorMapper_MapsKnownHResultsToDomainCodes(
        int hresult,
        FirewallRuleUpdateErrorCode expected)
    {
        Assert.Equal(expected, FirewallRuleUpdateErrorMapper.FromHResult(hresult));
    }

    [Theory]
    [InlineData(unchecked((int)0x80070005), "Access denied", "Administrator")]
    [InlineData(unchecked((int)0x800706D9), "Base Filtering Engine", "services are running")]
    public void ErrorMapper_ProducesActionablePlatformDiagnostics(
        int hresult,
        string expectedText,
        string expectedGuidance)
    {
        string message = FirewallRuleUpdateErrorMapper.DescribeHResult(hresult);

        Assert.Contains(expectedText, message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(expectedGuidance, message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"0x{hresult:X8}", message, StringComparison.OrdinalIgnoreCase);
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
