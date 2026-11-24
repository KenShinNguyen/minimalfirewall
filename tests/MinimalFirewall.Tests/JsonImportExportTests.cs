using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using MinimalFirewall.Tests.Fakes;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class JsonImportExportTests
{
    [Fact]
    public void ExportContainer_RoundTrip_PreservesAdvancedAndWildcardRules()
    {
        var source = new ExportContainer
        {
            ExportDate = new DateTime(2026, 11, 24, 12, 0, 0, DateTimeKind.Utc),
            AdvancedRules =
            [
                new AdvancedRuleViewModel
                {
                    Name = "MFW - Client",
                    IsEnabled = true,
                    Direction = Directions.Outgoing,
                    Protocol = 6,
                    ApplicationName = @"%ProgramFiles%\Client\client.exe",
                    Profiles = "All",
                    LocalPorts = "*",
                    RemotePorts = "*",
                    LocalAddresses = "*",
                    RemoteAddresses = "*",
                    Grouping = "Demo Group - MFW"
                }
            ],
            WildcardRules =
            [
                new WildcardRule
                {
                    FolderPath = @"%ProgramFiles%\Client\*",
                    ExeName = "client?.exe",
                    Action = "Allow Outbound"
                }
            ]
        };

        string json = JsonSerializer.Serialize(source, ExportContainerJsonContext.Default.ExportContainer);
        var roundTrip = JsonSerializer.Deserialize(json, ExportContainerJsonContext.Default.ExportContainer);

        Assert.NotNull(roundTrip);
        Assert.Equal(source.ExportDate, roundTrip!.ExportDate);
        Assert.Equal(source.AdvancedRules[0].ApplicationName, roundTrip.AdvancedRules[0].ApplicationName);
        Assert.Equal(source.WildcardRules[0].FolderPath, roundTrip.WildcardRules[0].FolderPath);
        Assert.Equal(source.WildcardRules[0].ExeName, roundTrip.WildcardRules[0].ExeName);
    }

    [Fact]
    public void Import_MalformedJson_ReturnsCleanFailureWithoutEnqueueing()
    {
        var backend = new InMemoryFirewallBackend();
        using var wildcard = CreateWildcardService();
        using var actions = CreateActionsService(backend, wildcard);
        using var queue = new BackgroundFirewallTaskService(
            actions,
            new UserActivityLogger(),
            wildcard,
            CreateDataService(backend, wildcard));

        actions.BackgroundTaskService = queue;

        bool accepted = actions.EnqueueImportTasks("{", replace: false, out int advancedCount, out int wildcardCount);

        Assert.False(accepted);
        Assert.Equal(0, advancedCount);
        Assert.Equal(0, wildcardCount);
    }

    [Fact]
    public async Task Import_ValidPayload_QueuesAdvancedAndWildcardEntries()
    {
        var backend = new InMemoryFirewallBackend();
        using var wildcard = CreateWildcardService();
        using var actions = CreateActionsService(backend, wildcard);
        using var queue = new BackgroundFirewallTaskService(
            actions,
            new UserActivityLogger(),
            wildcard,
            CreateDataService(backend, wildcard));

        actions.BackgroundTaskService = queue;

        var payload = new ExportContainer
        {
            ExportDate = DateTime.UtcNow,
            AdvancedRules =
            [
                new AdvancedRuleViewModel
                {
                    Name = "Imported Client",
                    IsEnabled = true,
                    Direction = Directions.Outgoing,
                    Protocol = 6,
                    ApplicationName = @"C:\WindowsApps\Imported\client.exe",
                    Profiles = "All",
                    LocalPorts = "*",
                    RemotePorts = "*",
                    LocalAddresses = "*",
                    RemoteAddresses = "*",
                    Grouping = "Imported Group - MFW"
                }
            ],
            WildcardRules =
            [
                new WildcardRule
                {
                    FolderPath = @"C:\WindowsApps\Imported\*",
                    ExeName = "*.exe",
                    Action = "Allow Outbound"
                }
            ]
        };

        string json = JsonSerializer.Serialize(payload, ExportContainerJsonContext.Default.ExportContainer);

        bool accepted = actions.EnqueueImportTasks(json, replace: false, out int advancedCount, out int wildcardCount);
        Assert.True(accepted);
        Assert.Equal(1, advancedCount);
        Assert.Equal(1, wildcardCount);

        await queue.WhenIdleAsync();

        Assert.Contains(backend.Rules, rule => rule.Name == "MFW - Imported Client");
        Assert.Single(wildcard.GetRules());
    }

    [Fact]
    public void Import_UnknownExtraProperties_IsIgnoredForForwardCompatibility()
    {
        const string json = """
        {
          "ExportDate": "2026-11-24T12:00:00Z",
          "AdvancedRules": [],
          "WildcardRules": [],
          "FutureProperty": "ignored"
        }
        """;

        var payload = JsonSerializer.Deserialize(json, ExportContainerJsonContext.Default.ExportContainer);

        Assert.NotNull(payload);
        Assert.Empty(payload!.AdvancedRules);
        Assert.Empty(payload.WildcardRules);
    }

    [Fact]
    public void Import_NullCollections_InitializesEmptyLists()
    {
        const string json = """
        {
          "ExportDate": "2026-11-24T12:00:00Z",
          "AdvancedRules": null,
          "WildcardRules": null
        }
        """;

        var payload = JsonSerializer.Deserialize(json, ExportContainerJsonContext.Default.ExportContainer);

        Assert.NotNull(payload);
        Assert.Empty(payload!.AdvancedRules);
        Assert.Empty(payload.WildcardRules);
    }

    private static WildcardRuleService CreateWildcardService()
        => new(Path.Combine(Path.GetTempPath(), $"mfw-json-wild-{Guid.NewGuid():N}.json"));

    private static FirewallActionsService CreateActionsService(
        InMemoryFirewallBackend backend,
        WildcardRuleService wildcard)
        => new(
            new UserActivityLogger(),
            null!,
            null!,
            null!,
            wildcard,
            CreateDataService(backend, wildcard),
            backend,
            backend,
            backend,
            backend,
            backend);

    private static FirewallDataService CreateDataService(
        InMemoryFirewallBackend backend,
        WildcardRuleService wildcard)
        => new(wildcard, null!, null!, backend);
}
