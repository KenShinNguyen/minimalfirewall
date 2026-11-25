using System;
using System.Collections.Generic;
using System.Linq;

namespace MinimalFirewall
{
    /// <summary>
    /// Phase 5B collection seam. Owns the rules-tab filter state and projection,
    /// leaving MainViewModel responsible for UI events and lifecycle orchestration.
    /// </summary>
    internal sealed class RulesCollectionCoordinator
    {
        private string _lastSearchText = string.Empty;
        private HashSet<RuleType> _lastEnabledTypes = [];
        private bool _lastShowSystemRules;

        internal SortableBindingList<AggregatedRuleViewModel> ApplyFilters(
            IEnumerable<AggregatedRuleViewModel> source,
            string searchText,
            HashSet<RuleType> enabledTypes,
            bool showSystemRules)
        {
            _lastSearchText = searchText;
            _lastEnabledTypes = new HashSet<RuleType>(enabledTypes);
            _lastShowSystemRules = showSystemRules;

            IEnumerable<AggregatedRuleViewModel> filteredRules = source;

            if (!showSystemRules)
            {
                filteredRules = filteredRules.Where(r =>
                    r.Grouping.EndsWith(" - MFW") || r.Type == RuleType.UWP);
            }

            if (enabledTypes.Count > 0 && enabledTypes.Count < 5)
            {
                filteredRules = filteredRules.Where(r => enabledTypes.Contains(r.Type));
            }

            if (!string.IsNullOrWhiteSpace(searchText))
            {
                filteredRules = filteredRules.Where(r =>
                    r.Name.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                    r.Description.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                    r.ApplicationName.Contains(searchText, StringComparison.OrdinalIgnoreCase));
            }

            return new SortableBindingList<AggregatedRuleViewModel>([.. filteredRules]);
        }

        internal SortableBindingList<AggregatedRuleViewModel> ReapplyLastFilters(
            IEnumerable<AggregatedRuleViewModel> source)
            => ApplyFilters(source, _lastSearchText, _lastEnabledTypes, _lastShowSystemRules);

        internal SortableBindingList<AggregatedRuleViewModel> Clear()
            => new([]);
    }
}
