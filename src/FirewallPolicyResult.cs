using NetFwTypeLib;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MinimalFirewall
{
    /// <summary>
    /// Tri-state result of reading a firewall default action.
    /// <see cref="Unknown"/> means the policy could not be read at all. It must never be
    /// collapsed into <see cref="Allow"/>: "we could not determine the state" and
    /// "the firewall is permitting traffic" are different facts, and treating the first
    /// as the second is how a firewall front-end silently reports the wrong protection level.
    /// </summary>
    public enum FirewallPolicyState
    {
        Unknown = 0,
        Allow,
        Block
    }

    /// <summary>
    /// Outcome of applying a default outbound action to one firewall profile.
    /// </summary>
    public sealed class ProfileActionResult
    {
        public NET_FW_PROFILE_TYPE2_ Profile { get; init; }
        public bool Succeeded { get; init; }

        /// <summary>Action the profile held before the change, when it could be read.</summary>
        public NET_FW_ACTION_? PreviousAction { get; init; }

        /// <summary>Populated only when <see cref="Succeeded"/> is false.</summary>
        public string? Error { get; init; }

        public string ProfileName => FirewallPolicyNames.Describe(Profile);
    }

    /// <summary>
    /// Outcome of <see cref="FirewallRuleService.SetDefaultOutboundAction"/> across all three
    /// profiles. A partial application is reported as a failure, not as success.
    /// </summary>
    public sealed class SetDefaultOutboundActionResult
    {
        public NET_FW_ACTION_ RequestedAction { get; init; }
        public IReadOnlyList<ProfileActionResult> Profiles { get; init; } = [];

        /// <summary>True when the firewall policy object itself could not be obtained.</summary>
        public bool PolicyUnavailable { get; init; }

        /// <summary>True when at least one profile was restored to its previous action after a failure.</summary>
        public bool RolledBack { get; init; }

        /// <summary>True when a rollback was attempted but did not fully succeed, leaving mixed profiles.</summary>
        public bool RollbackIncomplete { get; init; }

        public bool Succeeded =>
            !PolicyUnavailable && Profiles.Count > 0 && Profiles.All(p => p.Succeeded);

        public IEnumerable<ProfileActionResult> FailedProfiles => Profiles.Where(p => !p.Succeeded);

        /// <summary>Per-profile breakdown suitable for a log entry or an error dialog.</summary>
        public string BuildSummary()
        {
            if (PolicyUnavailable)
            {
                return "The Windows Firewall policy object could not be opened.";
            }

            var sb = new StringBuilder();
            foreach (var profile in Profiles)
            {
                sb.Append(profile.ProfileName)
                  .Append(": ")
                  .Append(profile.Succeeded ? "OK" : "FAILED")
                  .AppendLine(profile.Succeeded ? string.Empty : $" ({profile.Error})");
            }

            if (RollbackIncomplete)
            {
                sb.AppendLine("Rollback did not fully succeed - profiles may be in a mixed state.");
            }
            else if (RolledBack)
            {
                sb.AppendLine("Changes were rolled back to the previous policy.");
            }

            return sb.ToString().TrimEnd();
        }
    }

    internal static class FirewallPolicyNames
    {
        public static string Describe(NET_FW_PROFILE_TYPE2_ profile) => profile switch
        {
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN => "Domain",
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE => "Private",
            NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC => "Public",
            _ => profile.ToString()
        };
    }
}
