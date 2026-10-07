using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;
using SecureWebhooks.Tests.Infrastructure;

namespace SecureWebhooks.Tests.DependencyInjection;

public sealed class ServiceRegistrationTests : IAsyncLifetime
{
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;
    private LoopbackServer _server = null!;

    public async ValueTask InitializeAsync() => _server = await LoopbackServer.StartAsync();

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();

    private static IHost BuildHost(Action<WebhookSendingOptions>? sending = null, Action<WebhookDispatcherOptions>? dispatcher = null, string? key = null)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services
            .AddWebhookSending(o =>
            {
                o.AllowHttp = true;
                o.AllowedNetworks.Add(IPNetwork.Parse("127.0.0.0/8"));
                sending?.Invoke(o);
            })
            .AddAesGcmSecretProtection(o =>
            {
                o.Keys["2026-01"] = key ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                o.CurrentKeyId = "2026-01";
            })
            .AddWebhookDispatcher(o => dispatcher?.Invoke(o))
            .AddInMemoryWebhookStores();
        return builder.Build();
    }

    [Fact]
    public async Task Hosted_pipeline_delivers_a_verifiable_webhook_end_to_end()
    {
        using var host = BuildHost();
        await host.StartAsync(_ct);
        var services = host.Services;
        var secret = WebhookSecret.Generate();
        services.GetRequiredService<InMemoryWebhookEndpointStore>().Upsert(new WebhookEndpoint(
            "ep_1", _server.Url("/hooks"), [services.GetRequiredService<ISecretProtector>().Protect(secret, "ep_1")]));

        var id = await services.GetRequiredService<IWebhookPublisher>().EnqueueAsync("ep_1", "invoice.paid", "{\"total\":42}"u8.ToArray(), _ct);

        var deliveries = services.GetRequiredService<IWebhookDeliveryStore>();
        await DispatcherHarness.Eventually(async () => (await deliveries.GetAsync(id, _ct))?.Status == DeliveryStatus.Succeeded, "delivery to succeed");
        var request = Assert.Single(_server.Requests);
        Assert.Equal("{\"total\":42}", Encoding.UTF8.GetString(request.Body));
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            request.Body, request.Headers["webhook-id"], request.Headers["webhook-timestamp"], request.Headers["webhook-signature"], [secret], TimeProvider.System));
        await host.StopAsync(_ct);
    }

    [Fact]
    public async Task Invalid_options_fail_on_start()
    {
        using var host = BuildHost(dispatcher: o => o.MaxConcurrency = 0);

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(_ct));
        Assert.Contains(nameof(WebhookDispatcherOptions.MaxConcurrency), ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_timespan_options_fail_on_start()
    {
        using var host = BuildHost(sending: o => o.AttemptTimeout = TimeSpan.FromHours(1));

        await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(_ct));
    }

    [Fact]
    public async Task Invalid_key_ring_fails_on_start()
    {
        using var host = BuildHost(key: "too-short");

        await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(_ct));
    }

    [Fact]
    public void Named_client_uses_the_hardened_handler_without_url_logging_handlers()
    {
        using var host = BuildHost();

        HttpMessageHandler? handler = host.Services.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(WebhookSender.HttpClientName);
        var chain = new List<HttpMessageHandler>();
        while (handler is not null)
        {
            chain.Add(handler);
            handler = (handler as DelegatingHandler)?.InnerHandler;
        }

        var primary = Assert.IsType<SocketsHttpHandler>(chain[^1]);
        Assert.NotNull(primary.ConnectCallback);
        Assert.False(primary.UseProxy);
        Assert.False(primary.AllowAutoRedirect);
        Assert.DoesNotContain(chain, h => h.GetType().Name.Contains("Logging", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Attempts_emit_a_span_and_metrics()
    {
        var spans = new ConcurrentQueue<Activity>();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "SecureWebhooks",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = spans.Enqueue,
        };
        ActivitySource.AddActivityListener(activityListener);

        var instruments = new ConcurrentDictionary<string, long>();
        using var meterListener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecureWebhooks")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };
        meterListener.SetMeasurementEventCallback<long>((instrument, value, _, _) => instruments.AddOrUpdate(instrument.Name, value, (_, v) => v + value));
        meterListener.SetMeasurementEventCallback<double>((instrument, _, _, _) => instruments.AddOrUpdate(instrument.Name, 1, (_, v) => v + 1));
        meterListener.Start();

        using var host = BuildHost();
        var sender = host.Services.GetRequiredService<WebhookSender>();
        var protector = host.Services.GetRequiredService<ISecretProtector>();
        var endpoint = new WebhookEndpoint("ep_tel", _server.Url("/hooks"), [protector.Protect(WebhookSecret.Generate(), "ep_tel")]);

        var result = await sender.SendAsync(endpoint, SenderHarness.Message("msg_telemetry"), 3, _ct);

        Assert.Equal(AttemptOutcome.Success, result.Outcome);
        var span = Assert.Single(spans, s => (string?)s.GetTagItem("webhook.message_id") == "msg_telemetry");
        Assert.Equal("ep_tel", span.GetTagItem("webhook.endpoint_id"));
        Assert.Equal(3, span.GetTagItem("webhook.attempt"));
        Assert.Equal(200, span.GetTagItem("http.response.status_code"));
        Assert.Equal("Success", span.GetTagItem("webhook.outcome"));
        Assert.True(instruments.GetValueOrDefault("securewebhooks.attempts") >= 1);
        Assert.True(instruments.GetValueOrDefault("securewebhooks.succeeded") >= 1);
        Assert.True(instruments.GetValueOrDefault("securewebhooks.attempt.duration") >= 1);

        var dnsBlocked = new SsrfSafeConnectCallback(new IpAddressPolicy(), new FakeDnsResolver([IPAddress.Loopback]), null);
        using var client = new HttpClient(dnsBlocked.CreateHandler(new WebhookSendingOptions()));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://rebind.example.com:{_server.Port}/", _ct));
        Assert.True(instruments.GetValueOrDefault("securewebhooks.ssrf_blocked") >= 1);
    }
}
