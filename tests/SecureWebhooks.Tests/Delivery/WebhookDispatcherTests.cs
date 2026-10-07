using System.Net;
using System.Net.Http.Headers;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;
using SecureWebhooks.Tests.Infrastructure;

namespace SecureWebhooks.Tests.Delivery;

public sealed class WebhookDispatcherTests
{
    private static HttpResponseMessage Status(HttpStatusCode code) => new(code);

    [Fact]
    public async Task Enqueue_wakes_the_dispatcher_and_delivers_immediately()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK);
        h.AddEndpoint();
        await h.StartAsync();

        var id = await h.PublishAsync();

        await h.EventuallyStatus(id, DeliveryStatus.Succeeded);
        Assert.Equal(1, h.RequestCount);
        Assert.StartsWith("msg_", id, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Retries_keep_the_webhook_id_and_are_re_signed_with_fresh_timestamps()
    {
        int calls = 0;
        await using var h = new DispatcherHarness((_, _) => Task.FromResult(Status(Interlocked.Increment(ref calls) == 1 ? HttpStatusCode.InternalServerError : HttpStatusCode.OK)));
        h.AddEndpoint();
        await h.StartAsync();
        var start = h.Time.GetUtcNow();

        var id = await h.PublishAsync();
        await h.EventuallyAttempts(id, 1);

        var afterFirst = await h.GetAsync(id);
        Assert.Equal(DeliveryStatus.Pending, afterFirst.Status);
        Assert.InRange(afterFirst.NextAttemptAt, start + TimeSpan.FromSeconds(4), start + TimeSpan.FromSeconds(6)); // 5s ±20%

        h.Time.Advance(TimeSpan.FromSeconds(10));
        await h.EventuallyStatus(id, DeliveryStatus.Succeeded);

        var requests = h.Stub.Requests.ToArray();
        Assert.Equal(2, requests.Length);
        Assert.All(requests, r => Assert.Equal(id, r.Headers["webhook-id"]));
        Assert.NotEqual(requests[0].Headers["webhook-timestamp"], requests[1].Headers["webhook-timestamp"]);
        Assert.NotEqual(requests[0].Headers["webhook-signature"], requests[1].Headers["webhook-signature"]);
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            requests[1].Body, id, requests[1].Headers["webhook-timestamp"], requests[1].Headers["webhook-signature"], [h.Sender.Secret], h.Time));
        Assert.Equal(2, (await h.GetAsync(id)).AttemptCount);
    }

    [Fact]
    public async Task Gone_disables_the_endpoint_and_dead_letters_without_retry()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.Gone);
        h.AddEndpoint();
        await h.StartAsync();

        var id = await h.PublishAsync();
        await h.EventuallyStatus(id, DeliveryStatus.Failed);

        Assert.False((await h.Endpoints.GetAsync("ep_1", TestContext.Current.CancellationToken))!.IsEnabled);
        var next = await h.PublishAsync();
        await h.EventuallyStatus(next, DeliveryStatus.Failed);
        Assert.Equal(1, h.RequestCount);
        Assert.Contains(await h.Deliveries.ListAsync(DeliveryStatus.Failed, 10, TestContext.Current.CancellationToken), d => d.Message.Id == id);
    }

    [Fact]
    public async Task Permanent_failure_is_not_retried()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK);
        h.AddEndpoint(url: "https://169.254.169.254/latest/meta-data/");
        await h.StartAsync();

        var id = await h.PublishAsync();
        await h.EventuallyStatus(id, DeliveryStatus.Failed);
        h.Time.Advance(TimeSpan.FromDays(1));
        await Task.Delay(50, TestContext.Current.CancellationToken);

        var delivery = await h.GetAsync(id);
        Assert.Equal(1, delivery.AttemptCount);
        Assert.Equal(AttemptOutcome.Permanent, delivery.LastResult!.Outcome);
        Assert.Equal(0, h.RequestCount);
    }

    [Fact]
    public async Task Delivery_is_dead_lettered_after_the_last_scheduled_attempt()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.InternalServerError, o =>
        {
            o.RetrySchedule.Clear();
            o.RetrySchedule.Add(TimeSpan.Zero);
            o.RetrySchedule.Add(TimeSpan.FromSeconds(1));
            o.RetrySchedule.Add(TimeSpan.FromSeconds(1));
            o.CircuitBreakerThreshold = 100;
        });
        h.AddEndpoint();
        await h.StartAsync();

        var id = await h.PublishAsync();
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            await h.EventuallyAttempts(id, attempt);
            h.Time.Advance(h.Options.PollInterval);
        }

        await h.EventuallyStatus(id, DeliveryStatus.Failed);
        Assert.Equal(3, h.RequestCount);
    }

    [Fact]
    public async Task Retry_after_takes_precedence_over_a_shorter_schedule()
    {
        await using var h = new DispatcherHarness((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.TooManyRequests)
        {
            Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(10)) },
        }));
        h.AddEndpoint();
        await h.StartAsync();
        var start = h.Time.GetUtcNow();

        var id = await h.PublishAsync();
        await h.EventuallyAttempts(id, 1);

        Assert.Equal(start + TimeSpan.FromMinutes(10), (await h.GetAsync(id)).NextAttemptAt);
    }

    [Fact]
    public async Task Retry_after_is_capped_by_max_retry_after()
    {
        await using var h = new DispatcherHarness(
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromDays(7)) } }),
            o => o.MaxRetryAfter = TimeSpan.FromMinutes(30));
        h.AddEndpoint();
        await h.StartAsync();
        var start = h.Time.GetUtcNow();

        var id = await h.PublishAsync();
        await h.EventuallyAttempts(id, 1);

        Assert.Equal(start + TimeSpan.FromMinutes(30), (await h.GetAsync(id)).NextAttemptAt);
    }

    [Fact]
    public async Task Open_circuit_reschedules_without_consuming_an_attempt_then_probes_after_cooldown()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.InternalServerError, o =>
        {
            o.CircuitBreakerThreshold = 1;
            o.CircuitBreakerCooldown = TimeSpan.FromMinutes(1);
        });
        h.AddEndpoint();
        await h.StartAsync();
        var start = h.Time.GetUtcNow();

        var first = await h.PublishAsync();
        await h.EventuallyAttempts(first, 1); // circuit opens
        var second = await h.PublishAsync();
        await DispatcherHarness.Eventually(async () => (await h.GetAsync(second)) is { LeaseId: null, NextAttemptAt: var at } && at > start, "second to be rescheduled");

        var skipped = await h.GetAsync(second);
        Assert.Equal(0, skipped.AttemptCount);
        Assert.Equal(start + TimeSpan.FromMinutes(1), skipped.NextAttemptAt);
        Assert.Equal(1, h.RequestCount);

        h.Time.Advance(TimeSpan.FromMinutes(1));
        await DispatcherHarness.Eventually(() => h.RequestCount >= 2, "a probe after cooldown");
    }

    [Fact]
    public async Task Slow_endpoint_does_not_block_a_fast_one()
    {
        var release = new TaskCompletionSource();
        await using var h = new DispatcherHarness(
            async (request, ct) =>
            {
                if (request.Url.Host == "slow.example.com")
                {
                    await release.Task.WaitAsync(ct);
                }

                return Status(HttpStatusCode.OK);
            },
            o =>
            {
                o.MaxConcurrency = 4;
                o.MaxConcurrencyPerEndpoint = 2;
            });
        h.AddEndpoint("slow", "https://slow.example.com/");
        h.AddEndpoint("fast", "https://fast.example.com/");
        await h.StartAsync();

        for (int i = 0; i < 6; i++)
        {
            await h.PublishAsync("slow");
        }

        var fast = await h.PublishAsync("fast");

        await h.EventuallyStatus(fast, DeliveryStatus.Succeeded);
        Assert.Equal(2, h.Stub.Requests.Count(r => r.Url.Host == "slow.example.com")); // per-endpoint cap
        release.SetResult();
    }

    [Fact]
    public async Task Expired_lease_from_a_crashed_worker_is_redelivered()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK);
        h.AddEndpoint();
        var message = SenderHarness.Message("msg_crashed");
        await h.Deliveries.EnqueueAsync(new WebhookDelivery("ep_1", message, h.Time.GetUtcNow()), TestContext.Current.CancellationToken);
        await h.Deliveries.LeaseDueAsync(h.Time.GetUtcNow(), 10, TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken); // a worker leased it, then died

        await h.StartAsync();
        h.Time.Advance(h.Options.PollInterval);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.Equal(0, h.RequestCount);

        h.Time.Advance(TimeSpan.FromMinutes(1));
        await h.EventuallyStatus("msg_crashed", DeliveryStatus.Succeeded);
        Assert.Equal(1, h.RequestCount);
    }

    [Fact]
    public async Task Lease_duration_exceeds_twice_the_attempt_timeout()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK);

        Assert.True(h.Dispatcher.LeaseDuration > 2 * h.Sender.Options.AttemptTimeout);
    }

    [Fact]
    public async Task Graceful_shutdown_lets_in_flight_attempts_finish()
    {
        var release = new TaskCompletionSource();
        await using var h = new DispatcherHarness(async (_, ct) =>
        {
            await release.Task.WaitAsync(ct);
            return Status(HttpStatusCode.OK);
        });
        h.AddEndpoint();
        await h.StartAsync();
        var id = await h.PublishAsync();
        await DispatcherHarness.Eventually(() => h.RequestCount == 1, "attempt in flight");

        var stop = h.Dispatcher.StopAsync(TestContext.Current.CancellationToken);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(stop.IsCompleted);

        release.SetResult();
        await stop;
        Assert.Equal(DeliveryStatus.Succeeded, (await h.GetAsync(id)).Status);
    }

    [Fact]
    public async Task Shutdown_cancels_attempts_after_the_timeout_and_leaves_them_leased()
    {
        await using var h = new DispatcherHarness(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Status(HttpStatusCode.OK);
        });
        h.AddEndpoint();
        await h.StartAsync();
        var id = await h.PublishAsync();
        await DispatcherHarness.Eventually(() => h.RequestCount == 1, "attempt in flight");

        var stop = h.Dispatcher.StopAsync(TestContext.Current.CancellationToken);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        h.Time.Advance(h.Options.ShutdownTimeout);
        await stop.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        var delivery = await h.GetAsync(id);
        Assert.Equal(DeliveryStatus.Pending, delivery.Status);
        Assert.Equal(0, delivery.AttemptCount);
        Assert.NotNull(delivery.LeaseId); // still leased: redelivered after the lease expires (at-least-once)
    }

    [Fact]
    public async Task Endpoint_failing_longer_than_disable_after_is_disabled()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.InternalServerError, o =>
        {
            o.RetrySchedule.Clear();
            o.RetrySchedule.Add(TimeSpan.Zero);
            o.RetrySchedule.Add(TimeSpan.FromDays(3));
            o.RetrySchedule.Add(TimeSpan.FromDays(3));
            o.RetrySchedule.Add(TimeSpan.FromDays(3));
            o.CircuitBreakerThreshold = 100;
            o.DisableAfter = TimeSpan.FromDays(5);
        });
        h.AddEndpoint();
        await h.StartAsync();

        var id = await h.PublishAsync();
        await h.EventuallyAttempts(id, 1);
        h.Time.Advance(TimeSpan.FromDays(3.7));
        await h.EventuallyAttempts(id, 2);
        Assert.True((await h.Endpoints.GetAsync("ep_1", TestContext.Current.CancellationToken))!.IsEnabled);

        h.Time.Advance(TimeSpan.FromDays(3.7));
        await h.EventuallyAttempts(id, 3);
        Assert.False((await h.Endpoints.GetAsync("ep_1", TestContext.Current.CancellationToken))!.IsEnabled);
    }

    [Fact]
    public async Task Missing_endpoint_dead_letters_the_delivery()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK);
        await h.StartAsync();

        var id = await h.PublishAsync("does_not_exist");

        await h.EventuallyStatus(id, DeliveryStatus.Failed);
        Assert.Equal(0, h.RequestCount);
    }

    [Fact]
    public async Task Publisher_enforces_max_payload_size_and_copies_the_payload()
    {
        await using var h = new DispatcherHarness(HttpStatusCode.OK, o => o.MaxPayloadBytes = 16);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await h.Publisher.EnqueueAsync("ep_1", "x", new byte[17], TestContext.Current.CancellationToken));

        var payload = "{\"a\":1}"u8.ToArray();
        var id = await h.Publisher.EnqueueAsync("ep_1", "x", payload, TestContext.Current.CancellationToken);
        payload[0] = (byte)'X';
        Assert.Equal((byte)'{', (await h.GetAsync(id)).Message.Payload.Span[0]);
    }
}
