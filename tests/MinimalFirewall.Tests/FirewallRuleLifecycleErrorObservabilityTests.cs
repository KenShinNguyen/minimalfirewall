using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class FirewallRuleLifecycleErrorObservabilityTests
{
    [Fact]
    public void Execute_TranslatesUnauthorizedAccessToFailureResultWithHResultAndException()
    {
        var exception = new UnauthorizedAccessException("access denied");

        var result = InvokeExecute(() => throw exception);

        Assert.False(result.Succeeded);
        Assert.Same(exception, result.Exception);
        Assert.Equal(exception.HResult, result.HResult);
        Assert.Contains("access denied", result.Error);
    }

    [Fact]
    public void Execute_TranslatesComExceptionKeepingHResultAndException()
    {
        var exception = new COMException("service stopped", unchecked((int)0x800706D9));

        var result = InvokeExecute(() => throw exception);

        Assert.False(result.Succeeded);
        Assert.Same(exception, result.Exception);
        Assert.Equal(unchecked((int)0x800706D9), result.HResult);
        Assert.Contains("0x800706D9", result.Error);
    }

    [Fact]
    public void Execute_DoesNotSwallowArgumentException()
    {
        var ex = Assert.Throws<TargetInvocationException>(
            () => InvokeExecute(() => throw new ArgumentException("programming bug")));

        Assert.IsType<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public void LifecycleFailureWithException_IsLoggedThroughLogException()
    {
        var logger = new RecordingLogger();
        var exception = new UnauthorizedAccessException("access denied");
        var backend = new FailingBackend(
            FirewallRuleLifecycleOperationResult.Failure("delete rules by path failed", exception));
        var service = CreateService(logger, backend);

        service.DeleteApplicationRules(["C:\\Apps\\demo.exe"]);

        var logged = Assert.Single(logger.Exceptions);
        Assert.Same(exception, logged.Exception);
        Assert.Contains("C:\\Apps\\demo.exe", logged.Context);
        Assert.Empty(logger.DebugMessages);
    }

    [Fact]
    public void LifecycleFailureWithoutException_FallsBackToDebugLogWithError()
    {
        var logger = new RecordingLogger();
        var backend = new FailingBackend(
            FirewallRuleLifecycleOperationResult.Failure("simulated lifecycle failure"));
        var service = CreateService(logger, backend);

        service.DeleteApplicationRules(["C:\\Apps\\demo.exe"]);

        Assert.Empty(logger.Exceptions);
        var message = Assert.Single(logger.DebugMessages);
        Assert.Contains("simulated lifecycle failure", message);
    }

    private static FirewallRuleLifecycleOperationResult InvokeExecute(Action operation)
    {
        var method = typeof(WindowsFirewallRuleLifecycleBackend).GetMethod(
            "Execute",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("WindowsFirewallRuleLifecycleBackend.Execute was not found.");

        return (FirewallRuleLifecycleOperationResult)method.Invoke(null, [operation, "test operation"])!;
    }

    private static FirewallActionsService CreateService(UserActivityLogger logger, IFirewallRuleLifecycleBackend backend)
        => new(
            null!,
            logger,
            null!,
            null!,
            null!,
            null!,
            null!,
            null,
            null,
            backend);

    private sealed class RecordingLogger : UserActivityLogger
    {
        public List<(string Context, Exception Exception)> Exceptions { get; } = [];
        public List<string> DebugMessages { get; } = [];

        public override void LogException(string context, Exception ex) => Exceptions.Add((context, ex));

        public override void LogDebug(string message) => DebugMessages.Add(message);
    }

    private sealed class FailingBackend(FirewallRuleLifecycleOperationResult failure) : IFirewallRuleLifecycleBackend
    {
        public FirewallRuleLifecycleOperationResult DeleteByPath(IReadOnlyList<string> appPaths) => failure;
        public FirewallRuleLifecycleOperationResult DeleteUwp(IReadOnlyList<string> packageFamilyNames) => failure;
        public FirewallRuleLifecycleOperationResult DeleteByName(IReadOnlyList<string> ruleNames) => failure;
        public FirewallRuleLifecycleOperationResult DeleteByDescription(string description) => failure;
        public FirewallRuleLifecycleOperationResult DeleteByGroup(string groupName) => failure;
        public FirewallRuleLifecycleOperationResult DeleteAllMfwRules() => failure;
        public FirewallRuleLifecycleOperationResult EnableByName(string ruleName) => failure;
        public FirewallRuleLifecycleOperationResult DisableByName(string ruleName) => failure;
    }
}
