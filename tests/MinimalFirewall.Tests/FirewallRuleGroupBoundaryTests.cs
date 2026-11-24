using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using MinimalFirewall.Groups;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleGroupBoundaryTests
{
    [Fact]
    public void GroupSnapshot_ContainsOnlyPlainData()
    {
        var snapshot = new FirewallRuleGroupSnapshot(
            "@FirewallAPI.dll,-28752",
            3,
            true);

        Assert.Equal("@FirewallAPI.dll,-28752", snapshot.Name);
        Assert.Equal(3, snapshot.RuleCount);
        Assert.True(snapshot.IsEnabled);
        Assert.DoesNotContain(
            typeof(FirewallGroup)
                .GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
                .Select(field => field.FieldType.FullName ?? field.FieldType.Name),
            typeName => typeName.Contains("INetFw", StringComparison.Ordinal));
    }

    [Fact]
    public void Manager_GetAllGroups_UsesBackendSnapshots()
    {
        var backend = new RecordingGroupBackend
        {
            Groups =
            [
                new FirewallRuleGroupSnapshot("Z Group", 1, false),
                new FirewallRuleGroupSnapshot("@FirewallAPI.dll,-28752", 3, true)
            ]
        };

        var manager = new FirewallGroupManager(backend);
        var groups = manager.GetAllGroups();

        Assert.Equal(2, groups.Count);
        Assert.Equal("@FirewallAPI.dll,-28752", groups[0].Name);
        Assert.Equal(3, groups[0].RuleCount);
        Assert.True(groups[0].IsEnabled);
        Assert.Equal("Z Group", groups[1].Name);
        Assert.False(groups[1].IsEnabled);
        Assert.Equal(1, backend.GetGroupsCalls);
    }

    [Fact]
    public void Manager_GetAllGroups_PreservesBackendFailure()
    {
        var exception = new COMException(
            "access denied",
            unchecked((int)0x80070005));

        var backend = new RecordingGroupBackend
        {
            GetGroupsResult = FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>>.Failure(
                "query failed",
                exception)
        };

        var manager = new FirewallGroupManager(backend);

        var thrown = Assert.Throws<InvalidOperationException>(() => manager.GetAllGroups());

        Assert.Equal("query failed", thrown.Message);
        Assert.Same(exception, thrown.InnerException);
        Assert.Equal(exception.HResult, thrown.InnerException?.HResult);
    }

    [Fact]
    public void Manager_SetGroupEnabledState_RoutesToBackend()
    {
        var backend = new RecordingGroupBackend
        {
            SetGroupEnabledResult = FirewallRuleGroupResult<int>.Success(2)
        };

        var manager = new FirewallGroupManager(backend);

        var result = manager.SetGroupEnabledState("@FirewallAPI.dll,-28752", false);

        Assert.True(result.Succeeded);
        Assert.Equal(2, result.Value);
        Assert.Equal("@FirewallAPI.dll,-28752", backend.LastGroupName);
        Assert.False(backend.LastEnabledState);
        Assert.Equal(1, backend.SetGroupEnabledCalls);
    }

    [Fact]
    public void Group_SetEnabledState_UpdatesSnapshotOnly()
    {
        var backend = new RecordingGroupBackend();
        var manager = new FirewallGroupManager(backend);

        var group = Assert.Single(manager.GetAllGroups());
        Assert.True(group.IsEnabled);

        group.SetEnabledState(false);

        Assert.False(group.IsEnabled);
        Assert.Equal(0, backend.SetGroupEnabledCalls);
    }

    [Fact]
    public void Group_SetEnabledState_RaisesPropertyChangedOnce()
    {
        var backend = new RecordingGroupBackend();
        var manager = new FirewallGroupManager(backend);
        var group = Assert.Single(manager.GetAllGroups());

        int notifications = 0;
        group.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(FirewallGroup.IsEnabled))
            {
                notifications++;
            }
        };

        group.SetEnabledState(false);
        group.SetEnabledState(false);

        Assert.False(group.IsEnabled);
        Assert.Equal(1, notifications);
    }

    [Fact]
    public void BackendFailureResult_PreservesHResultAndException()
    {
        var exception = new COMException(
            "toggle failed",
            unchecked((int)0x80070005));

        var result = FirewallRuleGroupResult<int>.Failure(
            "toggle failed",
            exception);

        Assert.False(result.Succeeded);
        Assert.Equal("toggle failed", result.Error);
        Assert.Equal(exception.HResult, result.HResult);
        Assert.Same(exception, result.Exception);
    }

    private sealed class RecordingGroupBackend : IFirewallRuleGroupBackend
    {
        public IReadOnlyList<FirewallRuleGroupSnapshot> Groups { get; init; } =
        [
            new FirewallRuleGroupSnapshot("@FirewallAPI.dll,-28752", 2, true)
        ];

        public FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>> GetGroupsResult { get; init; } =
            FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>>.Success(Groups);

        public FirewallRuleGroupResult<int> SetGroupEnabledResult { get; init; } =
            FirewallRuleGroupResult<int>.Success(0);

        public int GetGroupsCalls { get; private set; }
        public int SetGroupEnabledCalls { get; private set; }
        public string? LastGroupName { get; private set; }
        public bool LastEnabledState { get; private set; }

        public FirewallRuleGroupResult<IReadOnlyList<FirewallRuleGroupSnapshot>> GetGroups()
        {
            GetGroupsCalls++;
            return GetGroupsResult;
        }

        public FirewallRuleGroupResult<int> SetGroupEnabled(string groupName, bool isEnabled)
        {
            SetGroupEnabledCalls++;
            LastGroupName = groupName;
            LastEnabledState = isEnabled;
            return SetGroupEnabledResult;
        }
    }
}
