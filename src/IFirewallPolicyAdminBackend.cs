using System;

namespace MinimalFirewall;

public sealed class FirewallPolicyAdminResult
{
    public bool Succeeded { get; init; }
    public string? Error { get; init; }
    public int? HResult { get; init; }
    public Exception? Exception { get; init; }

    public static FirewallPolicyAdminResult Success() => new()
    {
        Succeeded = true
    };

    public static FirewallPolicyAdminResult Failure(string error, Exception? exception = null) => new()
    {
        Succeeded = false,
        Error = error,
        HResult = exception?.HResult,
        Exception = exception
    };
}

public interface IFirewallPolicyAdminBackend
{
    FirewallPolicyAdminResult ResetFirewall();
}
