using System.IO;
using System.Text;
using System.Text.Json;
using MinimalFirewall.TypedObjects;

namespace MinimalFirewall;

internal sealed record FirewallConfigImportPreview(
    string FullPath,
    string JsonContent,
    int AdvancedRuleCount,
    int AllowRuleCount,
    int WildcardRuleCount);

/// <summary>
/// Owns the file-system and validation boundary for user-selected firewall backups.
/// Parsing and complete validation happen before any firewall task is enqueued.
/// </summary>
internal sealed class FirewallConfigTransferCoordinator
{
    internal const long DefaultMaximumImportFileBytes = 10L * 1024 * 1024;
    internal const int MaximumRulesPerCategory = 5000;
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private readonly long _maximumImportFileBytes;

    internal FirewallConfigTransferCoordinator(
        long maximumImportFileBytes = DefaultMaximumImportFileBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumImportFileBytes, 1);
        _maximumImportFileBytes = maximumImportFileBytes;
    }

    internal async Task<FirewallConfigImportPreview> ReadImportPreviewAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        string fullPath = Path.GetFullPath(filePath);

        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (stream.Length == 0)
        {
            throw new InvalidDataException("The selected firewall backup is empty.");
        }

        if (stream.Length > _maximumImportFileBytes)
        {
            throw new InvalidDataException(
                $"The selected firewall backup exceeds the {_maximumImportFileBytes:N0}-byte import limit.");
        }

        using var reader = new StreamReader(
            stream,
            StrictUtf8,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 64 * 1024,
            leaveOpen: true);

        string jsonContent = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        if (StrictUtf8.GetByteCount(jsonContent) > _maximumImportFileBytes)
        {
            throw new InvalidDataException(
                $"The selected firewall backup exceeds the {_maximumImportFileBytes:N0}-byte import limit.");
        }

        if (!TryDeserializeAndValidate(jsonContent, out ExportContainer? container, out string failureReason))
        {
            throw new InvalidDataException(failureReason);
        }

        var advancedRules = container!.AdvancedRules;
        return new FirewallConfigImportPreview(
            fullPath,
            jsonContent,
            advancedRules.Count,
            advancedRules.Count(rule => string.Equals(
                rule.Status,
                "Allow",
                StringComparison.OrdinalIgnoreCase)),
            container.WildcardRules.Count);
    }

    internal async Task ExportAsync(
        string filePath,
        Func<Task<string>> createJson,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(createJson);

        string fullPath = Path.GetFullPath(filePath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory))
        {
            throw new InvalidOperationException("The export destination must include a directory.");
        }

        Directory.CreateDirectory(directory);
        string temporaryPath = $"{fullPath}.{Guid.NewGuid():N}.tmp";

        try
        {
            string jsonContent = await createJson().ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(jsonContent))
            {
                throw new InvalidDataException("The firewall backup serializer returned no content.");
            }

            byte[] payload = StrictUtf8.GetBytes(jsonContent);
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            // The temporary file is in the destination directory, so replacement stays
            // on the same volume and does not expose a partially-written backup.
            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (IOException)
            {
                // Cleanup must not mask the export failure or damage the previous backup.
            }
            catch (UnauthorizedAccessException)
            {
                // Cleanup is best-effort; the unique temporary file is safe to retry manually.
            }
        }
    }

    internal static bool TryDeserializeAndValidate(
        string? jsonContent,
        out ExportContainer? container,
        out string failureReason)
    {
        container = null;
        failureReason = string.Empty;

        if (string.IsNullOrWhiteSpace(jsonContent))
        {
            failureReason = "The firewall backup is empty.";
            return false;
        }

        try
        {
            container = JsonSerializer.Deserialize(
                jsonContent,
                ExportContainerJsonContext.Default.ExportContainer);
        }
        catch (JsonException)
        {
            failureReason = "The selected file is not a valid Minimal Firewall rules backup.";
            return false;
        }
        catch (NotSupportedException)
        {
            failureReason = "The selected firewall backup uses an unsupported data format.";
            return false;
        }

        if (container is null)
        {
            failureReason = "The selected file does not contain a firewall backup.";
            return false;
        }

        if (container.AdvancedRules.Count > MaximumRulesPerCategory ||
            container.WildcardRules.Count > MaximumRulesPerCategory)
        {
            failureReason = $"A firewall backup cannot contain more than {MaximumRulesPerCategory:N0} rules of each category.";
            container = null;
            return false;
        }

        for (int index = 0; index < container.AdvancedRules.Count; index++)
        {
            AdvancedRuleViewModel? rule = container.AdvancedRules[index];
            if (rule is null)
            {
                failureReason = $"Advanced rule #{index + 1} is empty.";
                container = null;
                return false;
            }

            int direction = (int)rule.Direction;
            int allowedDirections = (int)(Directions.Incoming | Directions.Outgoing);
            if (string.IsNullOrWhiteSpace(rule.Name) ||
                !(string.Equals(rule.Status, "Allow", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(rule.Status, "Block", StringComparison.OrdinalIgnoreCase)) ||
                direction == 0 ||
                (direction & ~allowedDirections) != 0 ||
                rule.Protocol is < 0 or > 256)
            {
                failureReason = $"Advanced rule #{index + 1} has invalid required fields.";
                container = null;
                return false;
            }
        }

        for (int index = 0; index < container.WildcardRules.Count; index++)
        {
            WildcardRule? rule = container.WildcardRules[index];
            if (rule is null)
            {
                failureReason = $"Wildcard rule #{index + 1} is empty.";
                container = null;
                return false;
            }

            bool validAction =
                rule.Action.StartsWith("Allow", StringComparison.OrdinalIgnoreCase) ||
                rule.Action.StartsWith("Block", StringComparison.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(rule.FolderPath) ||
                !validAction ||
                rule.Protocol is < 0 or > 256)
            {
                failureReason = $"Wildcard rule #{index + 1} has invalid required fields.";
                container = null;
                return false;
            }
        }

        return true;
    }
}
