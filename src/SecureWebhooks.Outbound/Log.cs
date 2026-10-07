using System.Net;
using Microsoft.Extensions.Logging;

namespace SecureWebhooks.Outbound;

// Never log secrets, payloads or full URLs (query strings can carry tokens): scheme, host and port only.
internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Debug, "Blocked webhook connection to {Host}:{Port}: resolved address {Address} is not allowed")]
    public static partial void SsrfBlocked(ILogger logger, string host, int port, IPAddress address);
}
