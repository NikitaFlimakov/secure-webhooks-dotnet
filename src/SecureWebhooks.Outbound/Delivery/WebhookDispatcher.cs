using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecureWebhooks.Outbound;

/// <summary>
/// Leases due deliveries and runs them on a fixed worker pool. Semantics: at-least-once, no ordering guarantee.
/// A single pump leases only as many deliveries as there are free workers and skips endpoints that already have
/// <see cref="WebhookDispatcherOptions.MaxConcurrencyPerEndpoint"/> attempts in flight, so a slow endpoint cannot block others.
/// </summary>
internal sealed class WebhookDispatcher(
    IWebhookDeliveryStore deliveries,
    IWebhookEndpointStore endpoints,
    WebhookSender sender,
    DispatchSignal signal,
    IOptions<WebhookDispatcherOptions> options,
    IOptions<WebhookSendingOptions> sendingOptions,
    TimeProvider timeProvider,
    ILogger<WebhookDispatcher> logger) : BackgroundService
{
    private readonly WebhookDispatcherOptions _options = options.Value;
    private readonly CircuitBreaker _breaker = new(options.Value.CircuitBreakerThreshold, options.Value.CircuitBreakerCooldown);
    private readonly Dictionary<string, int> _inFlightPerEndpoint = new(StringComparer.Ordinal);
    private int _inFlight;

    /// <summary>A lease outlives one attempt with margin, so it only expires if the worker died.</summary>
    internal TimeSpan LeaseDuration { get; } = (2 * sendingOptions.Value.AttemptTimeout) + TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Capacity == worker count and the pump never has more than that in flight, so writes never wait.
        var work = Channel.CreateBounded<WebhookDelivery>(new BoundedChannelOptions(_options.MaxConcurrency) { SingleWriter = true });
        using var abort = new CancellationTokenSource();
        var workers = new Task[_options.MaxConcurrency];
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = Task.Run(() => WorkerAsync(work.Reader, abort.Token), CancellationToken.None);
        }

        var ticker = TickAsync(stoppingToken);
        try
        {
            await PumpAsync(work.Writer, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            // Graceful shutdown: stop leasing, give in-flight attempts ShutdownTimeout, then cancel them.
            work.Writer.TryComplete();
            using var deadline = timeProvider.CreateTimer(_ => abort.Cancel(), null, _options.ShutdownTimeout, Timeout.InfiniteTimeSpan);
            await Task.WhenAll(workers).ConfigureAwait(false);
            await ticker.ConfigureAwait(false);
        }
    }

    private async Task TickAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_options.PollInterval, timeProvider);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                signal.Notify();
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task PumpAsync(ChannelWriter<WebhookDelivery> work, CancellationToken cancellationToken)
    {
        while (true)
        {
            int free = _options.MaxConcurrency - Volatile.Read(ref _inFlight);
            if (free > 0)
            {
                try
                {
                    var now = timeProvider.GetUtcNow();
                    var due = await deliveries.LeaseDueAsync(now, free, LeaseDuration, cancellationToken).ConfigureAwait(false);
                    foreach (var delivery in due)
                    {
                        if (!TryReserve(delivery.EndpointId))
                        {
                            await deliveries.CompleteAsync(delivery with { NextAttemptAt = now + _options.PollInterval }, cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        Interlocked.Increment(ref _inFlight);
                        await work.WriteAsync(delivery, cancellationToken).ConfigureAwait(false);
                    }

                    if (due.Count == free)
                    {
                        continue; // more may be due
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Log.PumpFailed(logger, ex); // e.g. the store is unavailable; try again on the next tick
                }
            }

            await signal.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WorkerAsync(ChannelReader<WebhookDelivery> work, CancellationToken abort)
    {
        try
        {
            await foreach (var delivery in work.ReadAllAsync(abort).ConfigureAwait(false))
            {
                try
                {
                    await ProcessAsync(delivery, abort).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !abort.IsCancellationRequested)
                {
                    Log.ProcessingFailed(logger, delivery.Message.Id, ex); // the lease expires and the delivery is retried
                }
                finally
                {
                    Release(delivery.EndpointId);
                    Interlocked.Decrement(ref _inFlight);
                    signal.Notify();
                }
            }
        }
        catch (OperationCanceledException) when (abort.IsCancellationRequested)
        {
            // Shutdown deadline passed; unfinished leases expire and are redelivered.
        }
    }

    private async Task ProcessAsync(WebhookDelivery delivery, CancellationToken cancellationToken)
    {
        var endpoint = await endpoints.GetAsync(delivery.EndpointId, cancellationToken).ConfigureAwait(false);
        var now = timeProvider.GetUtcNow();
        if (endpoint is not { IsEnabled: true })
        {
            var result = new AttemptResult(AttemptOutcome.Permanent, null, TimeSpan.Zero, Error: "The endpoint does not exist or is disabled.");
            await CompleteAsync(delivery with { Status = DeliveryStatus.Failed, LastResult = result }, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (_breaker.TryAcquire(endpoint.Id, now) is { } retryAt)
        {
            await CompleteAsync(delivery with { NextAttemptAt = retryAt }, cancellationToken).ConfigureAwait(false); // no attempt consumed
            return;
        }

        int attempt = delivery.AttemptCount + 1;
        var attemptResult = await sender.SendAsync(endpoint, delivery.Message, attempt, cancellationToken).ConfigureAwait(false);
        now = timeProvider.GetUtcNow();
        var updated = delivery with { AttemptCount = attempt, LastResult = attemptResult };

        if (attemptResult.Outcome == AttemptOutcome.Success)
        {
            _breaker.RecordSuccess(endpoint.Id);
            await CompleteAsync(updated with { Status = DeliveryStatus.Succeeded }, cancellationToken).ConfigureAwait(false);
            return;
        }

        var (opened, failingFor) = _breaker.RecordFailure(endpoint.Id, now);
        if (opened)
        {
            OutboundTelemetry.CircuitOpened.Add(1);
            Log.CircuitOpened(logger, endpoint.Id);
        }

        string? disableReason = attemptResult.Outcome == AttemptOutcome.EndpointGone ? "The endpoint responded with 410 Gone."
            : _options.DisableAfter is { } limit && failingFor >= limit ? $"The endpoint has been failing for {failingFor}."
            : null;
        if (disableReason is not null)
        {
            await endpoints.DisableAsync(endpoint.Id, disableReason, cancellationToken).ConfigureAwait(false);
            Log.EndpointDisabled(logger, endpoint.Id, disableReason);
        }

        var delay = attemptResult.Outcome == AttemptOutcome.Retryable
            ? RetryPolicy.NextDelay(_options.RetrySchedule, attempt, attemptResult.RetryAfter, _options.MaxRetryAfter, Random.Shared.NextDouble())
            : null;
        await CompleteAsync(delay is { } d ? updated with { NextAttemptAt = now + d } : updated with { Status = DeliveryStatus.Failed }, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task CompleteAsync(WebhookDelivery delivery, CancellationToken cancellationToken)
    {
        if (!await deliveries.CompleteAsync(delivery, cancellationToken).ConfigureAwait(false))
        {
            Log.LeaseLost(logger, delivery.Message.Id);
        }
    }

    private bool TryReserve(string endpointId)
    {
        lock (_inFlightPerEndpoint)
        {
            _inFlightPerEndpoint.TryGetValue(endpointId, out int count);
            if (count >= _options.MaxConcurrencyPerEndpoint)
            {
                return false;
            }

            _inFlightPerEndpoint[endpointId] = count + 1;
            return true;
        }
    }

    private void Release(string endpointId)
    {
        lock (_inFlightPerEndpoint)
        {
            if (--_inFlightPerEndpoint[endpointId] == 0)
            {
                _inFlightPerEndpoint.Remove(endpointId);
            }
        }
    }
}
