namespace SecureWebhooks.Outbound;

/// <summary>A webhook destination.</summary>
/// <param name="Id">Stable endpoint id; also the associated data for secret encryption.</param>
/// <param name="Url">Destination URL. Never logged in full (queries can carry tokens).</param>
/// <param name="ProtectedSecrets">Secrets encrypted with <see cref="ISecretProtector"/>; all are used to sign (current first, then rotated-out ones).</param>
/// <param name="IsEnabled">Disabled endpoints receive no deliveries.</param>
public sealed record WebhookEndpoint(string Id, Uri Url, IReadOnlyList<string> ProtectedSecrets, bool IsEnabled = true);

/// <summary>A webhook message. The payload is serialized once at enqueue and sent byte-for-byte on every attempt.</summary>
/// <param name="Id">The <c>webhook-id</c>; identical across all attempts so receivers can deduplicate.</param>
/// <param name="EventType">Event type, e.g. <c>invoice.paid</c>.</param>
/// <param name="Payload">UTF-8 JSON body.</param>
public sealed record WebhookMessage(string Id, string EventType, ReadOnlyMemory<byte> Payload);

/// <summary>How an attempt should be treated by the caller.</summary>
public enum AttemptOutcome
{
    /// <summary>2xx response.</summary>
    Success,

    /// <summary>Non-2xx (other than 410), timeout or network error: retry later.</summary>
    Retryable,

    /// <summary>Invalid URL or SSRF-blocked destination: retrying will not help.</summary>
    Permanent,

    /// <summary>410 Gone: the receiver asked to stop; disable the endpoint.</summary>
    EndpointGone,
}

/// <summary>Result of one delivery attempt.</summary>
/// <param name="Outcome">Classification of the attempt.</param>
/// <param name="StatusCode">HTTP status code, if a response was received.</param>
/// <param name="Duration">Time spent on the attempt.</param>
/// <param name="RetryAfter">Delay requested by the receiver's <c>Retry-After</c> header, if any.</param>
/// <param name="Error">Sanitized error; never contains internal addresses. Safe to show to the endpoint owner.</param>
/// <param name="ResponseBodyPreview">Up to <see cref="WebhookSendingOptions.MaxResponseBodyBytes"/> of the response body, for diagnostics.</param>
public sealed record AttemptResult(
    AttemptOutcome Outcome,
    int? StatusCode,
    TimeSpan Duration,
    TimeSpan? RetryAfter = null,
    string? Error = null,
    string? ResponseBodyPreview = null);
