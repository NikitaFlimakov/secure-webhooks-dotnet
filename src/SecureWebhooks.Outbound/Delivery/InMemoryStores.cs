using System.Collections.Concurrent;

namespace SecureWebhooks.Outbound;

/// <summary>In-memory delivery store for tests and samples. Not durable: everything is lost on restart.</summary>
public sealed class InMemoryWebhookDeliveryStore : IWebhookDeliveryStore
{
    private readonly Dictionary<string, (WebhookDelivery Delivery, DateTimeOffset LeasedUntil)> _items = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask EnqueueAsync(WebhookDelivery delivery, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        lock (_items)
        {
            _items.Add(delivery.Message.Id, (delivery with { LeaseId = null }, DateTimeOffset.MinValue));
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WebhookDelivery>> LeaseDueAsync(DateTimeOffset now, int maxCount, TimeSpan leaseDuration, CancellationToken cancellationToken)
    {
        var leased = new List<WebhookDelivery>();
        lock (_items)
        {
            foreach (var (delivery, leasedUntil) in _items.Values)
            {
                if (leased.Count == maxCount)
                {
                    break;
                }

                if (delivery.Status == DeliveryStatus.Pending && delivery.NextAttemptAt <= now && leasedUntil <= now)
                {
                    leased.Add(delivery with { LeaseId = Guid.NewGuid().ToString("N") });
                }
            }

            foreach (var lease in leased)
            {
                _items[lease.Message.Id] = (lease, now + leaseDuration);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<WebhookDelivery>>(leased);
    }

    /// <inheritdoc />
    public ValueTask<bool> CompleteAsync(WebhookDelivery delivery, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        lock (_items)
        {
            if (!_items.TryGetValue(delivery.Message.Id, out var current) || current.Delivery.LeaseId is null || current.Delivery.LeaseId != delivery.LeaseId)
            {
                return ValueTask.FromResult(false);
            }

            _items[delivery.Message.Id] = (delivery with { LeaseId = null }, DateTimeOffset.MinValue);
            return ValueTask.FromResult(true);
        }
    }

    /// <inheritdoc />
    public ValueTask<WebhookDelivery?> GetAsync(string messageId, CancellationToken cancellationToken)
    {
        lock (_items)
        {
            return ValueTask.FromResult(_items.TryGetValue(messageId, out var item) ? item.Delivery : null);
        }
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WebhookDelivery>> ListAsync(DeliveryStatus status, int maxCount, CancellationToken cancellationToken)
    {
        lock (_items)
        {
            IReadOnlyList<WebhookDelivery> result = [.. _items.Values.Select(i => i.Delivery).Where(d => d.Status == status).Take(maxCount)];
            return ValueTask.FromResult(result);
        }
    }
}

/// <summary>In-memory endpoint store for tests and samples.</summary>
public sealed class InMemoryWebhookEndpointStore : IWebhookEndpointStore
{
    private readonly ConcurrentDictionary<string, WebhookEndpoint> _endpoints = new(StringComparer.Ordinal);

    /// <summary>Adds or replaces an endpoint.</summary>
    public void Upsert(WebhookEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        _endpoints[endpoint.Id] = endpoint;
    }

    /// <inheritdoc />
    public ValueTask<WebhookEndpoint?> GetAsync(string endpointId, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_endpoints.GetValueOrDefault(endpointId));

    /// <inheritdoc />
    public ValueTask DisableAsync(string endpointId, string reason, CancellationToken cancellationToken)
    {
        if (_endpoints.TryGetValue(endpointId, out var endpoint))
        {
            _endpoints[endpointId] = endpoint with { IsEnabled = false };
        }

        return ValueTask.CompletedTask;
    }
}
