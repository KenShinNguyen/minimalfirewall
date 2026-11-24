using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace MinimalFirewall.Groups
{
    public class FirewallGroup : INotifyPropertyChanged
    {
        public string Name { get; }
        public int RuleCount { get; }

        private bool _isEnabled;

        public event PropertyChangedEventHandler? PropertyChanged;

        public FirewallGroup(string name, int ruleCount, bool isEnabled)
        {
            Name = name;
            RuleCount = ruleCount;
            _isEnabled = isEnabled;
        }

        public bool IsEnabled
        {
            get => _isEnabled;
            private set
            {
                if (_isEnabled == value)
                {
                    return;
                }

                _isEnabled = value;
                PropertyChanged?.Invoke(
                    this,
                    new PropertyChangedEventArgs(nameof(IsEnabled)));
            }
        }

        // The background task owns persistence of the firewall state. This model only
        // updates its snapshot after the UI has queued the state-change operation.
        public void SetEnabledState(bool isEnabled)
        {
            IsEnabled = isEnabled;
        }
    }

    public class FirewallGroupManager
    {
        private readonly IFirewallRuleGroupBackend _backend;

        public FirewallGroupManager(IFirewallRuleGroupBackend? backend = null)
        {
            _backend = backend ?? new WindowsFirewallRuleGroupBackend();
        }

        public List<FirewallGroup> GetAllGroups()
        {
            var result = _backend.GetGroups();
            if (!result.Succeeded || result.Value is null)
            {
                throw new InvalidOperationException(
                    string.IsNullOrWhiteSpace(result.Error)
                        ? "Failed to load firewall rule groups."
                        : result.Error,
                    result.Exception);
            }

            return result.Value
                .OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase)
                .Select(group => new FirewallGroup(
                    group.Name,
                    group.RuleCount,
                    group.IsEnabled))
                .ToList();
        }

        public FirewallRuleGroupResult<int> SetGroupEnabledState(
            string groupName,
            bool isEnabled) =>
            _backend.SetGroupEnabled(groupName, isEnabled);
    }
}
