using System.Collections.Generic;
using System.Threading;

namespace MinimalFirewall;

/// <summary>
/// Boundary used by the firewall sentry to observe rule state without owning Windows Firewall COM.
/// </summary>
public interface IFirewallRuleObservationBackend
{
    /// <summary>
    /// Looks up one firewall rule by display name. Returns null when the rule is not available.
    /// </summary>
    AdvancedRuleViewModel? GetRuleByName(string ruleName);

    /// <summary>
    /// Returns the current non-Minimal-Firewall rule snapshot.
    /// </summary>
    List<AdvancedRuleViewModel> GetForeignRules(
        IProgress<int>? progress = null,
        CancellationToken token = default);
}
