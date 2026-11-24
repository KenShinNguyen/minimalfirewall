namespace MinimalFirewall;

internal readonly record struct AuditPolicySetting(Guid SubcategoryId, uint AuditingInformation);

/// <summary>
/// Temporarily adjusts the two Windows Filtering Platform audit subcategories while
/// Lockdown is active, then restores the exact policy that was present beforehand.
/// </summary>
internal sealed class WfpAuditPolicyLease
{
    internal static readonly Guid PacketDropSubcategory = new("0CCE9225-69AE-11D9-BED3-505054503030");
    internal static readonly Guid ConnectionSubcategory = new("0CCE9226-69AE-11D9-BED3-505054503030");

    private const uint AuditSuccess = 0x00000001;
    private const uint AuditFailure = 0x00000002;
    private const uint AuditNone = 0x00000004;

    private static readonly Guid[] Subcategories =
    [
        PacketDropSubcategory,
        ConnectionSubcategory
    ];

    private readonly Func<Guid, uint> _readPolicy;
    private readonly Action<IReadOnlyList<AuditPolicySetting>> _writePolicies;
    private readonly object _sync = new();
    private Dictionary<Guid, uint>? _originalPolicy;

    internal WfpAuditPolicyLease(
        Func<Guid, uint> readPolicy,
        Action<IReadOnlyList<AuditPolicySetting>> writePolicies)
    {
        ArgumentNullException.ThrowIfNull(readPolicy);
        ArgumentNullException.ThrowIfNull(writePolicies);
        _readPolicy = readPolicy;
        _writePolicies = writePolicies;
    }

    internal bool IsActive
    {
        get
        {
            lock (_sync)
            {
                return _originalPolicy != null;
            }
        }
    }

    internal void Enable()
    {
        lock (_sync)
        {
            if (_originalPolicy == null)
            {
                var snapshot = new Dictionary<Guid, uint>();
                foreach (Guid subcategory in Subcategories)
                {
                    snapshot.Add(subcategory, _readPolicy(subcategory));
                }

                // Publish only after every original value has been read successfully.
                _originalPolicy = snapshot;
            }

            uint packetDropOriginal = _originalPolicy[PacketDropSubcategory];
            uint connectionOriginal = _originalPolicy[ConnectionSubcategory];

            var desiredPolicy = new[]
            {
                new AuditPolicySetting(
                    PacketDropSubcategory,
                    (packetDropOriginal & ~AuditNone) | AuditFailure),
                new AuditPolicySetting(
                    ConnectionSubcategory,
                    (connectionOriginal & ~AuditSuccess) | AuditFailure)
            };

            _writePolicies(desiredPolicy);
        }
    }

    internal void Restore()
    {
        lock (_sync)
        {
            if (_originalPolicy == null)
            {
                return;
            }

            var originalSettings = Subcategories
                .Select(subcategory => new AuditPolicySetting(
                    subcategory,
                    _originalPolicy[subcategory]))
                .ToArray();

            // Retain the snapshot when the write fails so a later shutdown/retry can
            // attempt restoration again rather than silently losing the baseline.
            _writePolicies(originalSettings);
            _originalPolicy = null;
        }
    }
}
