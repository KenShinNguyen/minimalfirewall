using Xunit;

namespace MinimalFirewall.Tests;

public sealed class MainFormLifecycleSafetyTests
{
    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, true, true)]
    [InlineData(false, false, true)]
    public void ShouldSkipUiInvoke_BlocksTeardownOrMissingHandle(
        bool teardownInProgress,
        bool handleCreated,
        bool expected)
    {
        bool actual = MainForm.ShouldSkipUiInvoke(teardownInProgress, handleCreated);

        Assert.Equal(expected, actual);
    }
}
