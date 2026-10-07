using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SecureWebhooks.Outbound;
using Opts = Microsoft.Extensions.Options.Options;

namespace SecureWebhooks.Tests.Infrastructure;

/// <summary>A WebhookDispatcher over in-memory stores, a stub HTTP handler and a FakeTimeProvider.</summary>
internal sealed class DispatcherHarness : IAsyncDisposable
{
    public DispatcherHarness(Func<CapturedRequest, CancellationToken, Task<HttpResponseMessage>> respond, Action<WebhookDispatcherOptions>? configure = null)
    {
        Stub = new StubHandler(respond);
        Sender = SenderHarness.WithStub(Time, Stub);
        configure?.Invoke(Options);
        var signal = new DispatchSignal();
        Dispatcher = new WebhookDispatcher(Deliveries, Endpoints, Sender.Sender, signal, Opts.Create(Options), Opts.Create(Sender.Options), Time, NullLogger<WebhookDispatcher>.Instance);
        Publisher = new WebhookPublisher(Deliveries, signal, Opts.Create(Options), Time);
    }

    public DispatcherHarness(HttpStatusCode status, Action<WebhookDispatcherOptions>? configure = null)
        : this((_, _) => Task.FromResult(new HttpResponseMessage(status)), configure)
    {
    }

    public FakeTimeProvider Time { get; } = new(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));

    public InMemoryWebhookDeliveryStore Deliveries { get; } = new();

    public InMemoryWebhookEndpointStore Endpoints { get; } = new();

    public WebhookDispatcherOptions Options { get; } = new();

    public StubHandler Stub { get; }

    public SenderHarness Sender { get; }

    public WebhookDispatcher Dispatcher { get; }

    public IWebhookPublisher Publisher { get; }

    public WebhookEndpoint AddEndpoint(string id = "ep_1", string url = "https://hooks.example.com/receive")
    {
        var endpoint = Sender.Endpoint(new Uri(url), id);
        Endpoints.Upsert(endpoint);
        return endpoint;
    }

    public Task StartAsync() => Dispatcher.StartAsync(TestContext.Current.CancellationToken);

    public ValueTask<string> PublishAsync(string endpointId = "ep_1") =>
        Publisher.EnqueueAsync(endpointId, "invoice.paid", "{\"id\":1}"u8.ToArray(), TestContext.Current.CancellationToken);

    public async Task<WebhookDelivery> GetAsync(string messageId) => (await Deliveries.GetAsync(messageId, default))!;

    public int RequestCount => Stub.Requests.Count;

    /// <summary>Polls (in real time) until the condition holds; fails after 10 seconds.</summary>
    public static async Task Eventually(Func<Task<bool>> condition, string description)
    {
        var stopwatch = Stopwatch.StartNew();
        while (!await condition())
        {
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"Timed out waiting for: {description}");
            await Task.Delay(10);
        }
    }

    public static Task Eventually(Func<bool> condition, string description) => Eventually(() => Task.FromResult(condition()), description);

    public Task EventuallyStatus(string messageId, DeliveryStatus status) =>
        Eventually(async () => (await GetAsync(messageId)).Status == status, $"{messageId} to be {status}");

    public Task EventuallyAttempts(string messageId, int attempts) =>
        Eventually(async () => (await GetAsync(messageId)) is { AttemptCount: var n, LeaseId: null } && n == attempts, $"{messageId} to have {attempts} completed attempts");

    public async ValueTask DisposeAsync()
    {
        var stop = Dispatcher.StopAsync(CancellationToken.None);
        while (!stop.IsCompleted)
        {
            Time.Advance(TimeSpan.FromSeconds(1));
            await Task.WhenAny(stop, Task.Delay(10));
        }

        await stop;
        Dispatcher.Dispose();
    }
}
