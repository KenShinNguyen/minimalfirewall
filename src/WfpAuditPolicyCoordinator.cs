using System.Text.Json;

namespace MinimalFirewall;

public sealed record WfpAuditSubcategorySnapshot(
    string SubcategoryGuid,
    bool WasFailureAuditingEnabledBeforeApp,
    bool ModifiedByApp);

public sealed record WfpAuditRecoveryState(
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<WfpAuditSubcategorySnapshot> Subcategories);

public interface IWfpAuditPolicyBackend
{
    bool IsFailureAuditingEnabled(string subcategoryGuid);
    bool SetFailureAuditing(string subcategoryGuid, bool enable);
}

public interface IWfpAuditStateStore
{
    WfpAuditRecoveryState? Load();
    void Save(WfpAuditRecoveryState state);
    void Delete();
}

public sealed class FileWfpAuditStateStore : IWfpAuditStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _stateFilePath;

    public FileWfpAuditStateStore(string stateFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateFilePath);
        _stateFilePath = stateFilePath;
    }

    public WfpAuditRecoveryState? Load()
    {
        if (!File.Exists(_stateFilePath))
        {
            return null;
        }

        try
        {
            string json = File.ReadAllText(_stateFilePath);
            return JsonSerializer.Deserialize<WfpAuditRecoveryState>(json, JsonOptions);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void Save(WfpAuditRecoveryState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        string? directory = Path.GetDirectoryName(_stateFilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string tempPath = $"{_stateFilePath}.{Guid.NewGuid():N}.tmp";
        try
        {
            string json = JsonSerializer.Serialize(state, JsonOptions);
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _stateFilePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    public void Delete()
    {
        if (File.Exists(_stateFilePath))
        {
            File.Delete(_stateFilePath);
        }
    }
}

public sealed class WfpAuditPolicyCoordinator
{
    private static readonly string[] DefaultSubcategoryGuids =
    [
        WfpAuditPolicyLease.PacketDropSubcategory.ToString("D"),
        WfpAuditPolicyLease.ConnectionSubcategory.ToString("D")
    ];

    private readonly IWfpAuditPolicyBackend _backend;
    private readonly IWfpAuditStateStore _stateStore;
    private readonly IReadOnlyList<string> _subcategoryGuids;

    public WfpAuditPolicyCoordinator(
        IWfpAuditPolicyBackend backend,
        IWfpAuditStateStore stateStore,
        IReadOnlyList<string>? subcategoryGuids = null)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        _subcategoryGuids = subcategoryGuids ?? DefaultSubcategoryGuids;
    }

    public void EnableWithBaselineTracking()
    {
        WfpAuditRecoveryState? existingState = _stateStore.Load();
        if (existingState is not null)
        {
            foreach (WfpAuditSubcategorySnapshot item in existingState.Subcategories)
            {
                if (item.ModifiedByApp && !_backend.IsFailureAuditingEnabled(item.SubcategoryGuid))
                {
                    _backend.SetFailureAuditing(item.SubcategoryGuid, enable: true);
                }
            }

            return;
        }

        var snapshots = new List<WfpAuditSubcategorySnapshot>(_subcategoryGuids.Count);
        bool anyChangeNeeded = false;

        foreach (string guid in _subcategoryGuids)
        {
            bool alreadyEnabled = _backend.IsFailureAuditingEnabled(guid);
            bool needToEnable = !alreadyEnabled;
            anyChangeNeeded |= needToEnable;

            snapshots.Add(new WfpAuditSubcategorySnapshot(
                guid,
                alreadyEnabled,
                needToEnable));
        }

        if (!anyChangeNeeded)
        {
            return;
        }

        // Write-ahead: the baseline is durable before the first OS mutation.
        _stateStore.Save(new WfpAuditRecoveryState(DateTimeOffset.UtcNow, snapshots));

        foreach (WfpAuditSubcategorySnapshot item in snapshots)
        {
            if (item.ModifiedByApp)
            {
                _backend.SetFailureAuditing(item.SubcategoryGuid, enable: true);
            }
        }
    }

    public void RestoreBaseline()
    {
        WfpAuditRecoveryState? savedState = _stateStore.Load();
        if (savedState is null)
        {
            return;
        }

        foreach (WfpAuditSubcategorySnapshot item in savedState.Subcategories)
        {
            if (item.ModifiedByApp && !item.WasFailureAuditingEnabledBeforeApp)
            {
                if (!_backend.SetFailureAuditing(item.SubcategoryGuid, enable: false))
                {
                    return;
                }
            }
        }

        _stateStore.Delete();
    }
}
