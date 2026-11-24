using System;
using System.Linq;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallPolicyResultContractTests
{
    [Fact]
    public void DefaultPolicyState_IsUnknown()
    {
        Assert.Equal(FirewallPolicyState.Unknown, default(FirewallPolicyState));
    }

    [Theory]
    [InlineData(FirewallPolicyState.Allow, true, FirewallOutboundAction.Block)]
    [InlineData(FirewallPolicyState.Block, true, FirewallOutboundAction.Allow)]
    [InlineData(FirewallPolicyState.Unknown, false, FirewallOutboundAction.Allow)]
    public void ToggleAction_OnlyMapsKnownPolicyStates(
        FirewallPolicyState currentState,
        bool expectedSuccess,
        FirewallOutboundAction expectedAction)
    {
        var succeeded = FirewallPolicyGuard.TryGetToggleAction(
            currentState,
            out var targetAction);

        Assert.Equal(expectedSuccess, succeeded);
        Assert.Equal(expectedAction, targetAction);
    }

    [Fact]
    public void ToggleAction_RejectsUndefinedPolicyState()
    {
        var succeeded = FirewallPolicyGuard.TryGetToggleAction(
            (FirewallPolicyState)123,
            out var targetAction);

        Assert.False(succeeded);
        Assert.Equal(default, targetAction);
    }

    [Theory]
    [InlineData(1, "Domain")]
    [InlineData(2, "Private")]
    [InlineData(4, "Public")]
    [InlineData(8, "8")]
    [InlineData(123, "123")]
    public void ProfileActionResult_DescribesKnownAndUnknownProfiles(
        int profile,
        string expectedName)
    {
        var result = new ProfileActionResult { Profile = profile };

        Assert.Equal(expectedName, result.ProfileName);
    }

    [Fact]
    public void SetResult_IsNotSuccessfulWhenNoProfilesWereEvaluated()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RequestedAction = FirewallOutboundAction.Block
        };

        Assert.False(result.Succeeded);
        Assert.Empty(result.FailedProfiles);
    }

    [Fact]
    public void SetResult_IsSuccessfulWhenEveryProfileSucceeded()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RequestedAction = FirewallOutboundAction.Block,
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true, PreviousAction = FirewallOutboundAction.Allow },
                new ProfileActionResult { Profile = 2, Succeeded = true, PreviousAction = FirewallOutboundAction.Allow },
                new ProfileActionResult { Profile = 4, Succeeded = true, PreviousAction = FirewallOutboundAction.Allow }
            ]
        };

        Assert.True(result.Succeeded);
        Assert.Empty(result.FailedProfiles);
    }

    [Fact]
    public void SetResult_ReportsPartialProfileFailureAsFailure()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RequestedAction = FirewallOutboundAction.Block,
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true },
                new ProfileActionResult { Profile = 2, Succeeded = false, Error = "Access denied." },
                new ProfileActionResult { Profile = 4, Succeeded = true }
            ]
        };

        Assert.False(result.Succeeded);
        var failed = Assert.Single(result.FailedProfiles);
        Assert.Equal(2, failed.Profile);
        Assert.Equal("Access denied.", failed.Error);
    }

    [Fact]
    public void SetResult_IsNotSuccessfulWhenPolicyObjectIsUnavailable()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RequestedAction = FirewallOutboundAction.Allow,
            PolicyUnavailable = true,
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true },
                new ProfileActionResult { Profile = 2, Succeeded = true },
                new ProfileActionResult { Profile = 4, Succeeded = true }
            ]
        };

        Assert.False(result.Succeeded);
        Assert.Empty(result.FailedProfiles);
        Assert.Equal(
            "The Windows Firewall policy object could not be opened.",
            result.BuildSummary());
    }

    [Fact]
    public void SetResult_FailedProfilesContainsOnlyFailuresAndPreservesProfileOrder()
    {
        var domain = new ProfileActionResult { Profile = 1, Succeeded = false, Error = "Read failed." };
        var privateProfile = new ProfileActionResult { Profile = 2, Succeeded = true };
        var publicProfile = new ProfileActionResult { Profile = 4, Succeeded = false, Error = "Write failed." };
        var result = new SetDefaultOutboundActionResult
        {
            Profiles = [domain, privateProfile, publicProfile]
        };

        Assert.Equal(new[] { domain, publicProfile }, result.FailedProfiles);
    }

    [Fact]
    public void BuildSummary_ReportsSuccessfulProfileActions()
    {
        var result = new SetDefaultOutboundActionResult
        {
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true },
                new ProfileActionResult { Profile = 2, Succeeded = true },
                new ProfileActionResult { Profile = 4, Succeeded = true }
            ]
        };

        var summary = result.BuildSummary();

        Assert.Equal(
            string.Join(
                Environment.NewLine,
                "Domain: OK",
                "Private: OK",
                "Public: OK"),
            summary);
    }

    [Fact]
    public void BuildSummary_IncludesFailureDetailsWithoutMarkingPartialSuccessAsSuccess()
    {
        var result = new SetDefaultOutboundActionResult
        {
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true },
                new ProfileActionResult { Profile = 2, Succeeded = false, Error = "Access denied - administrator privileges are required." },
                new ProfileActionResult { Profile = 4, Succeeded = true }
            ]
        };

        var summary = result.BuildSummary();

        Assert.Contains("Domain: OK", summary);
        Assert.Contains("Private: FAILED (Access denied - administrator privileges are required.)", summary);
        Assert.Contains("Public: OK", summary);
        Assert.False(result.Succeeded);
    }

    [Fact]
    public void BuildSummary_ReportsSuccessfulRollback()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RolledBack = true,
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = true },
                new ProfileActionResult { Profile = 2, Succeeded = false, Error = "Write failed." }
            ]
        };

        var summary = result.BuildSummary();

        Assert.Contains("Changes were rolled back to the previous policy.", summary);
        Assert.DoesNotContain("Rollback did not fully succeed", summary);
    }

    [Fact]
    public void BuildSummary_ReportsIncompleteRollbackWhenRollbackFlagsConflict()
    {
        var result = new SetDefaultOutboundActionResult
        {
            RolledBack = true,
            RollbackIncomplete = true,
            Profiles =
            [
                new ProfileActionResult { Profile = 1, Succeeded = false, Error = "Restore failed." }
            ]
        };

        var summary = result.BuildSummary();

        Assert.Contains(
            "Rollback did not fully succeed - profiles may be in a mixed state.",
            summary);
        Assert.DoesNotContain("Changes were rolled back to the previous policy.", summary);
    }

    [Fact]
    public void BuildSummary_ReturnsEmptyTextWhenThereAreNoProfilesOrPolicyFailure()
    {
        var result = new SetDefaultOutboundActionResult();

        Assert.Equal(string.Empty, result.BuildSummary());
    }

    [Fact]
    public void BuildSummary_UsesNumericLabelForUnknownProfile()
    {
        var result = new SetDefaultOutboundActionResult
        {
            Profiles =
            [
                new ProfileActionResult { Profile = 99, Succeeded = false, Error = "Unavailable." }
            ]
        };

        Assert.Equal("99: FAILED (Unavailable.)", result.BuildSummary());
    }
}
