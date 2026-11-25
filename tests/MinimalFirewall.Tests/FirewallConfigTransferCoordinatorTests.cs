using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallConfigTransferCoordinatorTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"mfw-transfer-tests-{Guid.NewGuid():N}");

    public FirewallConfigTransferCoordinatorTests()
        => Directory.CreateDirectory(_directory);

    [Fact]
    public void TryDeserializeAndValidate_MalformedOrEmptyJson_ReturnsCleanFailure()
    {
        Assert.False(FirewallConfigTransferCoordinator.TryDeserializeAndValidate(
            string.Empty,
            out ExportContainer? empty,
            out string emptyError));
        Assert.Null(empty);
        Assert.Contains("empty", emptyError, StringComparison.OrdinalIgnoreCase);

        Assert.False(FirewallConfigTransferCoordinator.TryDeserializeAndValidate(
            "{",
            out ExportContainer? malformed,
            out string malformedError));
        Assert.Null(malformed);
        Assert.Contains("valid", malformedError, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserializeAndValidate_RejectsOversizedJsonBeforeParsing()
    {
        string oversized = new string(' ', 33);

        bool valid = FirewallConfigTransferCoordinator.TryDeserializeAndValidate(
            oversized,
            out ExportContainer? result,
            out string failureReason,
            maximumJsonBytes: 32);

        Assert.False(valid);
        Assert.Null(result);
        Assert.Contains("32-byte", failureReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserializeAndValidate_InvalidRuleFields_RejectsWholePayload()
    {
        var invalid = new ExportContainer
        {
            AdvancedRules =
            [
                new AdvancedRuleViewModel
                {
                    Name = string.Empty,
                    Status = "Allow",
                    Direction = Directions.Outgoing,
                    Protocol = 6
                }
            ]
        };
        string json = JsonSerializer.Serialize(
            invalid,
            ExportContainerJsonContext.Default.ExportContainer);

        Assert.False(FirewallConfigTransferCoordinator.TryDeserializeAndValidate(
            json,
            out ExportContainer? result,
            out string failureReason));
        Assert.Null(result);
        Assert.Contains("Advanced rule #1", failureReason);
    }

    [Fact]
    public void TryDeserializeAndValidate_ValidLegacyShapeAndUnknownProperties_RemainsCompatible()
    {
        const string json = """
        {
          "ExportDate": "2026-11-24T12:00:00Z",
          "AdvancedRules": [],
          "WildcardRules": null,
          "FutureProperty": "ignored"
        }
        """;

        bool valid = FirewallConfigTransferCoordinator.TryDeserializeAndValidate(
            json,
            out ExportContainer? result,
            out string failureReason);

        Assert.True(valid, failureReason);
        Assert.NotNull(result);
        Assert.Empty(result!.AdvancedRules);
        Assert.Empty(result.WildcardRules);
    }

    [Fact]
    public async Task ReadImportPreviewAsync_RejectsFilesAboveConfiguredLimit()
    {
        string path = Path.Combine(_directory, "oversized.json");
        await File.WriteAllTextAsync(path, new string('x', 33));
        var coordinator = new FirewallConfigTransferCoordinator(maximumImportFileBytes: 32);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => coordinator.ReadImportPreviewAsync(path));
    }

    [Fact]
    public async Task ReadImportPreviewAsync_ReturnsCountsAndCanonicalFullPath()
    {
        string path = Path.Combine(_directory, ".", "backup.json");
        var container = new ExportContainer
        {
            ExportDate = DateTime.UtcNow,
            AdvancedRules =
            [
                new AdvancedRuleViewModel
                {
                    Name = "Allow Client",
                    Status = "Allow",
                    Direction = Directions.Outgoing,
                    Protocol = 6
                }
            ],
            WildcardRules =
            [
                new WildcardRule
                {
                    FolderPath = @"%ProgramFiles%\Client\*",
                    ExeName = "*.exe",
                    Action = "Block Outbound"
                }
            ]
        };
        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(container, ExportContainerJsonContext.Default.ExportContainer));

        var preview = await new FirewallConfigTransferCoordinator().ReadImportPreviewAsync(path);

        Assert.Equal(Path.GetFullPath(path), preview.FullPath);
        Assert.Equal(1, preview.AdvancedRuleCount);
        Assert.Equal(1, preview.AllowRuleCount);
        Assert.Equal(1, preview.WildcardRuleCount);
    }

    [Fact]
    public async Task ExportAsync_WhenSerializationFails_PreservesExistingDestination()
    {
        string path = Path.Combine(_directory, "existing.json");
        await File.WriteAllTextAsync(path, "previous-good-backup");
        var coordinator = new FirewallConfigTransferCoordinator();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => coordinator.ExportAsync(
                path,
                () => throw new InvalidOperationException("serializer failed")));

        Assert.Equal("previous-good-backup", await File.ReadAllTextAsync(path));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public async Task ExportAsync_ReplacesDestinationOnlyAfterCompleteTemporaryWrite()
    {
        string path = Path.Combine(_directory, "backup.json");
        await File.WriteAllTextAsync(path, "old");
        var coordinator = new FirewallConfigTransferCoordinator();

        await coordinator.ExportAsync(path, () => Task.FromResult("{\"ExportDate\":\"2026-11-25T00:00:00Z\"}"));

        Assert.Contains("ExportDate", await File.ReadAllTextAsync(path));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
