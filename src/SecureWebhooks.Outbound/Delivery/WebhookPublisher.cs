using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace SecureWebhooks.Outbound;

/// <summary>Wakes the dispatcher immediately on enqueue; coalesces bursts into one wake-up.</summary>
internal sealed class DispatchSignal
{
    private readonly Channel<bool> _channel = Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });

    public void Notify() => _channel.Writer.TryWrite(true);

    public ValueTask<bool> WaitAsync(CancellationToken cancellationToken) => _channel.Reader.ReadAsync(cancellationToken);
}

internal sealed class WebhookPublisher(IWebhookDeliveryStore store, DispatchSignal signal, IOptions<WebhookDispatcherOptions> options, TimeProvider timeProvider)
    : IWebhookPublisher
{
    public async ValueTask<string> EnqueueAsync(string endpointId, string eventType, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(endpointId);
        ArgumentException.ThrowIfNullOrEmpty(eventType);
        if (payload.Length > options.Value.MaxPayloadBytes)
        {
            throw new ArgumentException($"Payload exceeds {options.Value.MaxPayloadBytes} bytes.", nameof(payload));
        }

        var message = new WebhookMessage("msg_" + Guid.NewGuid().ToString("N"), eventType, payload.ToArray());
        var firstDelay = options.Value.RetrySchedule.Count > 0 ? options.Value.RetrySchedule[0] : TimeSpan.Zero;
        await store.EnqueueAsync(new WebhookDelivery(endpointId, message, timeProvider.GetUtcNow() + firstDelay), cancellationToken).ConfigureAwait(false);
        signal.Notify();
        return message.Id;
    }
}
