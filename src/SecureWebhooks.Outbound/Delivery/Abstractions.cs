namespace SecureWebhooks.Outbound;

/// <summary>Lifecycle state of a delivery.</summary>
public enum DeliveryStatus
{
    /// <summary>Waiting for its next attempt (or currently leased by a worker).</summary>
    Pending,

    /// <summary>Delivered with a 2xx response.</summary>
    Succeeded,

    /// <summary>Dead-lettered: retries exhausted, permanent failure, or the endpoint is gone/disabled.</summary>
    Failed,
}

/// <summary>One message destined for one endpoint, plus its retry state.</summary>
/// <param name="EndpointId">Destination endpoint.</param>
/// <param name="Message">The message; its id is the delivery id.</param>
/// <param name="NextAttemptAt">When the delivery becomes due.</param>
public sealed record WebhookDelivery(string EndpointId, WebhookMessage Message, DateTimeOffset NextAttemptAt)
{
    /// <summary>Current status.</summary>
    public DeliveryStatus Status { get; init; }

    /// <summary>Attempts made so far (attempts skipped by an open circuit breaker are not counted).</summary>
    public int AttemptCount { get; init; }

    /// <summary>Result of the most recent attempt.</summary>
    public AttemptResult? LastResult { get; init; }

    /// <summary>Set by <see cref="IWebhookDeliveryStore.LeaseDueAsync"/>; completions must present the same lease id.</summary>
    public string? LeaseId { get; init; }
}

/// <summary>Reads and disables endpoints. Implement over your own endpoint table.</summary>
public interface IWebhookEndpointStore
{
    /// <summary>Returns the endpoint, or <see langword="null"/> if it does not exist.</summary>
    ValueTask<WebhookEndpoint?> GetAsync(string endpointId, CancellationToken cancellationToken);

    /// <summary>Disables the endpoint (e.g. after HTTP 410 or prolonged failure).</summary>
    ValueTask DisableAsync(string endpointId, string reason, CancellationToken cancellationToken);
}

/// <summary>
/// Durable delivery queue. A SQL implementation maps each method to one statement: lease with
/// <c>UPDATE … SET lease_id = @new, leased_until = @now + @duration WHERE status = 'Pending' AND next_attempt_at &lt;= @now
/// AND (leased_until IS NULL OR leased_until &lt; @now) … RETURNING *</c> (or <c>FOR UPDATE SKIP LOCKED</c>), and complete with
/// <c>UPDATE … WHERE id = @id AND lease_id = @leaseId</c>.
/// </summary>
public interface IWebhookDeliveryStore
{
    /// <summary>Adds a new pending delivery.</summary>
    ValueTask EnqueueAsync(WebhookDelivery delivery, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically leases up to <paramref name="maxCount"/> pending deliveries that are due at <paramref name="now"/> and not
    /// currently leased. Leases expire after <paramref name="leaseDuration"/>, so deliveries held by a crashed worker are retried.
    /// </summary>
    ValueTask<IReadOnlyList<WebhookDelivery>> LeaseDueAsync(DateTimeOffset now, int maxCount, TimeSpan leaseDuration, CancellationToken cancellationToken);

    /// <summary>
    /// Stores the updated delivery and releases its lease, but only if <see cref="WebhookDelivery.LeaseId"/> still matches.
    /// Returns <see langword="false"/> if the lease was lost (another worker re-leased it after expiry).
    /// </summary>
    ValueTask<bool> CompleteAsync(WebhookDelivery delivery, CancellationToken cancellationToken);

    /// <summary>Returns a delivery by message id.</summary>
    ValueTask<WebhookDelivery?> GetAsync(string messageId, CancellationToken cancellationToken);

    /// <summary>Lists deliveries in a given status, e.g. <see cref="DeliveryStatus.Failed"/> for the dead-letter view.</summary>
    ValueTask<IReadOnlyList<WebhookDelivery>> ListAsync(DeliveryStatus status, int maxCount, CancellationToken cancellationToken);
}

/// <summary>Enqueues webhooks for background delivery.</summary>
public interface IWebhookPublisher
{
    /// <summary>
    /// Enqueues <paramref name="payload"/> (UTF-8 JSON, copied) for <paramref name="endpointId"/> and returns the generated
    /// <c>webhook-id</c>. Delivery is at-least-once with no ordering guarantee.
    /// </summary>
    /// <exception cref="ArgumentException">The payload exceeds <see cref="WebhookDispatcherOptions.MaxPayloadBytes"/>.</exception>
    ValueTask<string> EnqueueAsync(string endpointId, string eventType, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken);
}
