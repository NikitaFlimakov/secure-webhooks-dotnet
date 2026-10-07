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

    public static void AttemptCompleted(ILogger logger, string endpointId, string scheme, string host, int port, int attempt, int? statusCode, AttemptOutcome outcome, string? error) =>
        AttemptCompleted(logger, outcome == AttemptOutcome.Success ? LogLevel.Debug : LogLevel.Warning, endpointId, scheme, host, port, attempt, outcome, statusCode, error);
}
