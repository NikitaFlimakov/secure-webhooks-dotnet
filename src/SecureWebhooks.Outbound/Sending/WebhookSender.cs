using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Outbound;

/// <summary>
/// Sends a single, freshly signed delivery attempt. No retries: use it directly from Hangfire, Quartz or a queue consumer,
/// or let the dispatcher drive it.
/// </summary>
public sealed class WebhookSender(
    IHttpClientFactory httpClientFactory,
    ISecretProtector secretProtector,
    WebhookUrlValidator urlValidator,
    IOptions<WebhookSendingOptions> options,
    TimeProvider timeProvider,
    ILogger<WebhookSender>? logger = null)
{
    /// <summary>Name of the <see cref="HttpClient"/> registered by <c>AddWebhookSending</c>.</summary>
    public const string HttpClientName = "SecureWebhooks";

    private static readonly string UserAgent = "SecureWebhooks/" +
        (typeof(WebhookSender).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0");

    private readonly ILogger _logger = logger ?? NullLogger<WebhookSender>.Instance;

    /// <summary>Sends one attempt.</summary>
    public Task<AttemptResult> SendAsync(WebhookEndpoint endpoint, WebhookMessage message, CancellationToken cancellationToken) =>
        SendAsync(endpoint, message, 1, cancellationToken);

    /// <summary>Sends one attempt, signed with the current time. <paramref name="attempt"/> is used for telemetry only.</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<AttemptResult> SendAsync(WebhookEndpoint endpoint, WebhookMessage message, int attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(message);

        using var activity = OutboundTelemetry.ActivitySource.StartActivity("webhook.attempt", ActivityKind.Client);
        activity?.SetTag("webhook.endpoint_id", endpoint.Id);
        activity?.SetTag("webhook.message_id", message.Id);
        activity?.SetTag("webhook.attempt", attempt);

        long started = timeProvider.GetTimestamp();
        var result = await SendCoreAsync(endpoint, message, cancellationToken).ConfigureAwait(false);
        result = result with { Duration = timeProvider.GetElapsedTime(started) };

        activity?.SetTag("http.response.status_code", result.StatusCode);
        activity?.SetTag("webhook.outcome", result.Outcome.ToString());
        activity?.SetStatus(result.Outcome == AttemptOutcome.Success ? ActivityStatusCode.Ok : ActivityStatusCode.Error, result.Error);
        OutboundTelemetry.RecordAttempt(result);
        Log.AttemptCompleted(_logger, endpoint.Id, endpoint.Url.Scheme, endpoint.Url.Host, endpoint.Url.Port, attempt, result.StatusCode, result.Outcome, result.Error);
        return result;
    }

    private async Task<AttemptResult> SendCoreAsync(WebhookEndpoint endpoint, WebhookMessage message, CancellationToken cancellationToken)
    {
        var validation = urlValidator.Validate(endpoint.Url);
        if (!validation.IsValid)
        {
            return new AttemptResult(AttemptOutcome.Permanent, null, default, Error: validation.Error);
        }

        string signature;
        var now = timeProvider.GetUtcNow();
        try
        {
            var secrets = new WebhookSecret[endpoint.ProtectedSecrets.Count];
            for (int i = 0; i < secrets.Length; i++)
            {
                secrets[i] = secretProtector.Unprotect(endpoint.ProtectedSecrets[i], endpoint.Id);
            }

            signature = WebhookSigner.Sign(message.Id, now, message.Payload.Span, secrets);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // Usually a key-ring misconfiguration an operator can fix, so the attempt is retryable.
            return new AttemptResult(AttemptOutcome.Retryable, null, default, Error: "The endpoint secret could not be used for signing.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Url) { Content = new ReadOnlyMemoryContent(message.Payload) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation(WebhookHeaders.Id, message.Id);
        request.Headers.TryAddWithoutValidation(WebhookHeaders.Timestamp, now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(WebhookHeaders.Signature, signature);
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var timeout = new CancellationTokenSource(options.Value.AttemptTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            var client = httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            int status = (int)response.StatusCode;
            string preview = await ReadPreviewAsync(response.Content, options.Value.MaxResponseBodyBytes, linked.Token).ConfigureAwait(false);
            var outcome = status switch
            {
                >= 200 and < 300 => AttemptOutcome.Success,
                410 => AttemptOutcome.EndpointGone,
                _ => AttemptOutcome.Retryable,
            };
            return new AttemptResult(outcome, status, default, GetRetryAfter(response.Headers.RetryAfter, now),
                outcome == AttemptOutcome.Success ? null : $"The endpoint responded with HTTP {status}.", preview);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return new AttemptResult(AttemptOutcome.Retryable, null, default, Error: "The request timed out.");
        }
        catch (HttpRequestException ex) when (ex.InnerException is SsrfBlockedException blocked)
        {
            return new AttemptResult(AttemptOutcome.Permanent, null, default, Error: blocked.Message);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            // Exception messages can contain resolved IP addresses; only the error category is exposed.
            var category = ex is HttpRequestException { HttpRequestError: var error and not HttpRequestError.Unknown } ? error.ToString() : "NetworkError";
            return new AttemptResult(AttemptOutcome.Retryable, null, default, Error: $"The request failed: {category}.");
        }
    }

    private static async Task<string> ReadPreviewAsync(HttpContent content, int maxBytes, CancellationToken cancellationToken)
    {
        var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(maxBytes);
            try
            {
                int total = 0, read;
                while (total < maxBytes && (read = await stream.ReadAsync(buffer.AsMemory(total, maxBytes - total), cancellationToken).ConfigureAwait(false)) > 0)
                {
                    total += read;
                }

                return Encoding.UTF8.GetString(buffer, 0, total);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    private static TimeSpan? GetRetryAfter(RetryConditionHeaderValue? header, DateTimeOffset now) => header switch
    {
        { Delta: { } delta } => delta,
        { Date: { } date } => date > now ? date - now : TimeSpan.Zero,
        _ => null,
    };
}
