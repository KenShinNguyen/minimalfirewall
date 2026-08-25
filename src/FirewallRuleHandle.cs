using NetFwTypeLib;
using System;
using System.Runtime.InteropServices;

namespace MinimalFirewall
{
    /// <summary>
    /// Owns the lifetime of a single COM firewall rule so callers do not have to remember
    /// a matching <see cref="Marshal.ReleaseComObject"/>. Every early return, exception path
    /// and <c>continue</c> inside a <c>using</c> block releases the underlying object exactly once.
    /// </summary>
    public sealed class FirewallRuleHandle : IDisposable
    {
        private INetFwRule2? _rule;

        internal FirewallRuleHandle(INetFwRule2 rule)
        {
            _rule = rule ?? throw new ArgumentNullException(nameof(rule));
        }

        public INetFwRule2 Rule =>
            _rule ?? throw new ObjectDisposedException(nameof(FirewallRuleHandle));

        public bool IsDisposed => _rule == null;

        public void Dispose()
        {
            var rule = _rule;
            _rule = null;
            if (rule != null)
            {
                try
                {
                    Marshal.ReleaseComObject(rule);
                }
                catch (ArgumentException)
                {
                    // Not an RCW (already released elsewhere) - nothing left to free.
                }
            }
        }
    }
}
