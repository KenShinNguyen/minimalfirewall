using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleCreationBoundaryTests
{
    [Theory]
    [InlineData(FirewallRuleCreationAction.Allow, 1)]
    [InlineData(FirewallRuleCreationAction.Block, 0)]
    public void ActionMapping_IsExplicit(FirewallRuleCreationAction action, int expected)
    {
        Assert.Equal(expected, FirewallRuleCreationMapper.MapActionValue(action));
    }

    [Theory]
    [InlineData(FirewallRuleCreationDirection.Incoming, 1)]
    [InlineData(FirewallRuleCreationDirection.Outgoing, 2)]
    public void DirectionMapping_IsExplicit(FirewallRuleCreationDirection direction, int expected)
    {
        Assert.Equal(expected, FirewallRuleCreationMapper.MapDirectionValue(direction));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(6, 6)]
    [InlineData(17, 17)]
    [InlineData(58, 58)]
    [InlineData(256, 256)]
    [InlineData(123, 123)]
    public void ProtocolMapping_PreservesSupportedValues(int protocol, int expected)
    {
        Assert.Equal(expected, FirewallRuleCreationMapper.MapProtocol(protocol));
    }

    [Fact]
    public void ProtocolMapping_RejectsNegativeAndOversizedValues()
    {
        Assert.Throws<ArgumentException>(() => FirewallRuleCreationMapper.MapProtocol(-1));
        Assert.Throws<ArgumentException>(() => FirewallRuleCreationMapper.MapProtocol(257));
    }

    [Theory]
    [InlineData("Domain", 1)]
    [InlineData("Private", 2)]
    [InlineData("Public", 4)]
    [InlineData("Domain,Private", 3)]
    [InlineData("Domain,Public", 5)]
    [InlineData("Private,Public", 6)]
    [InlineData("Domain,Private,Public", 7)]
    [InlineData("All", int.MaxValue)]
    public void ProfileMapping_UsesExplicitFlags(string profiles, int expected)
    {
        var parsed = FirewallRuleCreationMapper.ParseProfiles(profiles);

        Assert.Equal(expected, FirewallRuleCreationMapper.MapProfileMask(parsed));
    }

    [Fact]
    public void ProfileMapping_EmptyProfileDefaultsToAll()
    {
        Assert.Equal(int.MaxValue, FirewallRuleCreationMapper.MapProfileMask(
            FirewallRuleCreationMapper.ParseProfiles("")));
    }

    [Fact]
    public void FromViewModel_ProducesPureCSharpDefinition()
    {
        var vm = new AdvancedRuleViewModel
        {
            Name = "MFW - Demo",
            Description = "demo",
            IsEnabled = true,
            Grouping = "Minimal Firewall - MFW",
            Status = "Allow",
            Direction = Directions.Outgoing,
            Protocol = 6,
            ApplicationName = @"C:\Apps\demo.exe",
            ServiceName = "DemoSvc",
            LocalPorts = "443",
            RemotePorts = "80",
            LocalAddresses = "*",
            RemoteAddresses = "10.0.0.1",
            Profiles = "Domain,Public",
            IcmpTypesAndCodes = ""
        };

        var definition = FirewallRuleCreationMapper.FromViewModel(vm, "Lan", "");

        Assert.Equal(FirewallRuleCreationAction.Allow, definition.Action);
        Assert.Equal(FirewallRuleCreationDirection.Outgoing, definition.Direction);
        Assert.Equal(6, definition.Protocol);
        Assert.Equal(FirewallRuleCreationProfile.Domain | FirewallRuleCreationProfile.Public, definition.Profiles);
        Assert.Equal("Lan", definition.InterfaceTypes);
        Assert.Equal("443", definition.LocalPorts);
        Assert.Equal("80", definition.RemotePorts);
    }

    [Fact]
    public void FromViewModel_RejectsCombinedDirections()
    {
        var vm = new AdvancedRuleViewModel
        {
            Direction = Directions.Incoming | Directions.Outgoing,
            Protocol = 6,
            Profiles = "All"
        };

        Assert.Throws<ArgumentException>(() =>
            FirewallRuleCreationMapper.FromViewModel(vm, "All", ""));
    }

    [Fact]
    public void CreateAdvancedRule_UsesCreationBackend()
    {
        var backend = new RecordingCreationBackend();
        var service = CreateService(backend);

        service.CreateAdvancedRule(
            new AdvancedRuleViewModel
            {
                Name = "Demo",
                Status = "Allow",
                IsEnabled = true,
                Grouping = "Minimal Firewall - MFW",
                Direction = Directions.Incoming,
                Protocol = 6,
                Profiles = "Domain,Public",
                LocalPorts = "443",
                RemotePorts = "*"
            },
            "All",
            "");

        var definition = Assert.Single(backend.Definitions);
        Assert.Equal("MFW - Demo", definition.Name);
        Assert.Equal(FirewallRuleCreationDirection.Incoming, definition.Direction);
        Assert.Equal(FirewallRuleCreationAction.Allow, definition.Action);
        Assert.Equal(6, definition.Protocol);
    }

    [Fact]
    public void CreateAdvancedRule_BatchFailure_UsesUiSeam()
    {
        var exception = new COMException("create failed", unchecked((int)0x80070057));
        var backend = new RecordingCreationBackend
        {
            Result = FirewallRuleCreationResult.Failure("create failed", exception)
        };
        var service = new TestableFirewallActionsService(backend);

        service.CreateAdvancedRule(
            new AdvancedRuleViewModel
            {
                Name = "Demo",
                Status = "Allow",
                IsEnabled = true,
                Grouping = "Minimal Firewall - MFW",
                Direction = Directions.Incoming,
                Protocol = 6,
                Profiles = "All"
            },
            "All",
            "");

        Assert.Contains("Created 0 rules successfully.", service.ShownMessage);
        Assert.Contains("Failed to create 1 rules:", service.ShownMessage);
        Assert.Contains("create failed", service.ShownMessage);
    }

    private static FirewallActionsService CreateService(IFirewallRuleCreationBackend backend) =>
        new(
            null!,
            new UserActivityLogger(),
            null!,
            null!,
            null!,
            null!,
            null!,
            null,
            null,
            null,
            null,
            backend);

    private sealed class RecordingCreationBackend : IFirewallRuleCreationBackend
    {
        public List<FirewallRuleCreationDefinition> Definitions { get; } = [];
        public FirewallRuleCreationResult Result { get; init; } = FirewallRuleCreationResult.Success();

        public FirewallRuleCreationResult CreateRule(FirewallRuleCreationDefinition definition)
        {
            Definitions.Add(definition);
            return Result;
        }
    }

    private sealed class TestableFirewallActionsService : FirewallActionsService
    {
        public string ShownMessage { get; private set; } = string.Empty;

        public TestableFirewallActionsService(IFirewallRuleCreationBackend backend)
            : base(
                null!,
                new UserActivityLogger(),
                null!,
                null!,
                null!,
                null!,
                null!,
                null,
                null,
                null,
                null,
                backend)
        {
        }

        protected override void ShowBatchCreationErrors(string text)
        {
            ShownMessage = text;
        }
    }
}
