namespace MinimalFirewall;

public enum FirewallRuleUpdateErrorCode
{
    None = 0,
    InvalidRequest,
    FirewallUnavailable,
    RuleNotFound,
    AccessDenied,
    OperationFailed
}

/// <summary>
/// Result of updating a firewall rule. Deliberately contains no Exception reference:
/// Windows/COM implementation details must not cross the backend boundary.
/// </summary>
public sealed class FirewallRuleUpdateResult
{
    public bool Succeeded { get; init; }
    public FirewallRuleUpdateErrorCode ErrorCode { get; init; }
    public string? Error { get; init; }
    public int? HResult { get; init; }

    public static FirewallRuleUpdateResult Success() => new()
    {
        Succeeded = true,
        ErrorCode = FirewallRuleUpdateErrorCode.None
    };

    public static FirewallRuleUpdateResult Failure(
        FirewallRuleUpdateErrorCode errorCode,
        string error,
        int? hresult = null)
    {
        if (errorCode == FirewallRuleUpdateErrorCode.None)
        {
            throw new ArgumentOutOfRangeException(nameof(errorCode), "A failure must have a non-success error code.");
        }

        return new FirewallRuleUpdateResult
        {
            Succeeded = false,
            ErrorCode = errorCode,
            Error = error,
            HResult = hresult
        };
    }
}

/// <summary>
/// Maps stable HRESULT values into application-level update error categories.
/// The mapper intentionally accepts an integer, not a Windows or COM exception.
/// </summary>
public static class FirewallRuleUpdateErrorMapper
{
    public static FirewallRuleUpdateErrorCode FromHResult(int hresult)
    {
        if (hresult == unchecked((int)0x80070005))
        {
            return FirewallRuleUpdateErrorCode.AccessDenied;
        }

        if (hresult == unchecked((int)0x80070002) ||
            hresult == unchecked((int)0x80070490))
        {
            return FirewallRuleUpdateErrorCode.RuleNotFound;
        }

        return FirewallRuleUpdateErrorCode.OperationFailed;
    }
}

/// <summary>
/// Boundary for updating mutable firewall-rule properties without exposing Windows Firewall COM types.
/// </summary>
public interface IFirewallRuleUpdateBackend
{
    FirewallRuleUpdateResult UpdateRemoteAddresses(string ruleName, string newRemoteAddresses);
}
