using System.Net;
using Microsoft.Extensions.Logging;

namespace SecureWebhooks.Outbound;

// Never log secrets, payloads or full URLs (query strings can carry tokens): scheme, host and port only.
internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Debug, "Blocked webhook connection to {Host}:{Port}: resolved address {Address} is not allowed")]
    public static partial void SsrfBlocked(ILogger logger, string host, int port, IPAddress address);

    [LoggerMessage(EventId = 2, Message = "Webhook attempt {Attempt} to endpoint {EndpointId} ({Scheme}://{Host}:{Port}): {Outcome} {StatusCode} {Error}")]
    private static partial void AttemptCompleted(ILogger logger, LogLevel level, string endpointId, string scheme, string host, int port, int attempt, AttemptOutcome outcome, int? statusCode, string? error);

    [LoggerMessage(3, LogLevel.Warning, "Circuit opened for webhook endpoint {EndpointId}")]
    public static partial void CircuitOpened(ILogger logger, string endpointId);

    [LoggerMessage(4, LogLevel.Warning, "Disabled webhook endpoint {EndpointId}: {Reason}")]
    public static partial void EndpointDisabled(ILogger logger, string endpointId, string reason);

    [LoggerMessage(5, LogLevel.Error, "Webhook dispatcher failed to lease deliveries")]
    public static partial void PumpFailed(ILogger logger, Exception exception);

    [LoggerMessage(6, LogLevel.Error, "Processing webhook delivery {MessageId} failed; it will be retried when its lease expires")]
    public static partial void ProcessingFailed(ILogger logger, string messageId, Exception exception);

    [LoggerMessage(7, LogLevel.Information, "Lease for webhook delivery {MessageId} was lost before completion; another worker owns it")]
    public static partial void LeaseLost(ILogger logger, string messageId);

    public static void AttemptCompleted(ILogger logger, string endpointId, string scheme, string host, int port, int attempt, int? statusCode, AttemptOutcome outcome, string? error) =>
        AttemptCompleted(logger, outcome == AttemptOutcome.Success ? LogLevel.Debug : LogLevel.Warning, endpointId, scheme, host, port, attempt, outcome, statusCode, error);
}
