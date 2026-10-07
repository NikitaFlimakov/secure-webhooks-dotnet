using System.Net;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;
using SecureWebhooks.Tests.Infrastructure;

namespace SecureWebhooks.Tests.Sending;

/// <summary>WebhookSender over the real hardened handler against Kestrel on loopback.</summary>
public sealed class WebhookSenderIntegrationTests : IAsyncLifetime
{
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;
    private LoopbackServer _server = null!;

    public async ValueTask InitializeAsync() => _server = await LoopbackServer.StartAsync();

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();

    private static SenderHarness Allowed(IDnsResolver? dns = null) => SenderHarness.WithHardenedHandler(TimeProvider.System, dns, o =>
    {
        o.AllowHttp = true;
        foreach (var network in SenderHarness.Loopback)
        {
            o.AllowedNetworks.Add(network);
        }
    });

    [Fact]
    public async Task Delivers_a_verifiable_webhook_when_loopback_is_allowed()
    {
        var harness = Allowed();

        var result = await harness.Sender.SendAsync(harness.Endpoint(_server.Url("/hooks")), SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Success, result.Outcome);
        Assert.Equal("ok", result.ResponseBodyPreview);
        var request = Assert.Single(_server.Requests);
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            request.Body, request.Headers["webhook-id"], request.Headers["webhook-timestamp"], request.Headers["webhook-signature"], [harness.Secret], TimeProvider.System));
    }

    [Fact]
    public async Task Host_resolving_to_loopback_is_blocked_permanently_with_a_sanitized_error()
    {
        var harness = SenderHarness.WithHardenedHandler(TimeProvider.System, new FakeDnsResolver([IPAddress.Loopback]));
        var url = new Uri($"https://hooks.example.com:{_server.Port}/hooks");

        var result = await harness.Sender.SendAsync(harness.Endpoint(url), SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Permanent, result.Outcome);
        Assert.DoesNotContain("127.0.0.1", result.Error, StringComparison.Ordinal);
        Assert.Empty(_server.Requests);
    }

    [Fact]
    public async Task Redirect_to_metadata_service_is_not_followed()
    {
        var harness = Allowed();

        var result = await harness.Sender.SendAsync(harness.Endpoint(_server.Url("/redirect")), SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Retryable, result.Outcome);
        Assert.Equal(302, result.StatusCode);
        Assert.Single(_server.Requests);
    }

    [Fact]
    public async Task Oversized_response_body_is_not_read_beyond_the_limit()
    {
        var harness = Allowed();

        var result = await harness.Sender.SendAsync(harness.Endpoint(_server.Url("/big")), SenderHarness.Message(), _ct);

        Assert.True(result.Outcome == AttemptOutcome.Success, $"{result.Outcome} {result.StatusCode} {result.Error}");
        Assert.Equal(harness.Options.MaxResponseBodyBytes, result.ResponseBodyPreview!.Length);
        await Task.Delay(500, _ct); // let the server observe the closed connection
        // Socket buffers on both sides plus SocketsHttpHandler's bounded drain (1 MB) can absorb a few MB, never 64 MB.
        long written = Interlocked.Read(ref _server.BigBodyBytesWritten);
        Assert.True(written < 32L * 1024 * 1024, $"the server streamed {written} bytes; the client should have stopped reading long before 64 MB");
    }
}
