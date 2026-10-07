using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Time.Testing;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;
using SecureWebhooks.Tests.Infrastructure;

namespace SecureWebhooks.Tests.Sending;

public sealed class WebhookSenderTests
{
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;

    [Fact]
    public async Task Sends_signed_standard_webhooks_request()
    {
        var stub = StubHandler.Status(HttpStatusCode.OK);
        var harness = SenderHarness.WithStub(_time, stub);
        var message = SenderHarness.Message();

        var result = await harness.Sender.SendAsync(harness.Endpoint(), message, _ct);

        Assert.Equal(AttemptOutcome.Success, result.Outcome);
        Assert.Equal(200, result.StatusCode);
        var request = Assert.Single(stub.Requests);
        Assert.Equal("msg_1", request.Headers["webhook-id"]);
        Assert.Equal("1700000000", request.Headers["webhook-timestamp"]);
        Assert.Equal("application/json", request.ContentType);
        Assert.StartsWith("SecureWebhooks/", request.Headers["User-Agent"], StringComparison.Ordinal);
        Assert.Equal(message.Payload.ToArray(), request.Body);
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            request.Body, request.Headers["webhook-id"], request.Headers["webhook-timestamp"], request.Headers["webhook-signature"], [harness.Secret], _time));
    }

    [Fact]
    public async Task Signs_with_every_secret_during_rotation()
    {
        var stub = StubHandler.Status(HttpStatusCode.OK);
        var harness = SenderHarness.WithStub(_time, stub);
        var previous = WebhookSecret.Generate();

        await harness.Sender.SendAsync(harness.Endpoint(extraSecrets: previous), SenderHarness.Message(), _ct);

        var request = Assert.Single(stub.Requests);
        Assert.Equal(2, request.Headers["webhook-signature"].Split(' ').Length);
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            request.Body, "msg_1", "1700000000", request.Headers["webhook-signature"], [previous], _time));
    }

    [Fact]
    public async Task Each_attempt_is_re_signed_with_a_fresh_timestamp_but_keeps_the_message_id()
    {
        var stub = StubHandler.Status(HttpStatusCode.InternalServerError);
        var harness = SenderHarness.WithStub(_time, stub);
        var endpoint = harness.Endpoint();

        await harness.Sender.SendAsync(endpoint, SenderHarness.Message(), _ct);
        _time.Advance(TimeSpan.FromMinutes(10));
        await harness.Sender.SendAsync(endpoint, SenderHarness.Message(), 2, _ct);

        var requests = stub.Requests.ToArray();
        Assert.Equal(requests[0].Headers["webhook-id"], requests[1].Headers["webhook-id"]);
        Assert.Equal("1700000600", requests[1].Headers["webhook-timestamp"]);
        Assert.NotEqual(requests[0].Headers["webhook-signature"], requests[1].Headers["webhook-signature"]);
        Assert.Equal(VerificationResult.Valid, WebhookVerifier.Verify(
            requests[1].Body, "msg_1", "1700000600", requests[1].Headers["webhook-signature"], [harness.Secret], _time));
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, AttemptOutcome.Success)]
    [InlineData(HttpStatusCode.NoContent, AttemptOutcome.Success)]
    [InlineData(HttpStatusCode.Gone, AttemptOutcome.EndpointGone)]
    [InlineData(HttpStatusCode.Found, AttemptOutcome.Retryable)]
    [InlineData(HttpStatusCode.BadRequest, AttemptOutcome.Retryable)]
    [InlineData(HttpStatusCode.NotFound, AttemptOutcome.Retryable)]
    [InlineData(HttpStatusCode.TooManyRequests, AttemptOutcome.Retryable)]
    [InlineData(HttpStatusCode.InternalServerError, AttemptOutcome.Retryable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, AttemptOutcome.Retryable)]
    public async Task Classifies_status_codes(HttpStatusCode status, AttemptOutcome expected)
    {
        var harness = SenderHarness.WithStub(_time, StubHandler.Status(status));

        var result = await harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), _ct);

        Assert.Equal(expected, result.Outcome);
        Assert.Equal((int)status, result.StatusCode);
    }

    [Fact]
    public async Task Parses_retry_after_delta_seconds()
    {
        var harness = SenderHarness.WithStub(_time, new StubHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120)) } })));

        var result = await harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), _ct);

        Assert.Equal(TimeSpan.FromSeconds(120), result.RetryAfter);
    }

    [Fact]
    public async Task Parses_retry_after_http_date()
    {
        var harness = SenderHarness.WithStub(_time, new StubHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new RetryConditionHeaderValue(_time.GetUtcNow().AddMinutes(5)) } })));

        var result = await harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), _ct);

        Assert.Equal(TimeSpan.FromMinutes(5), result.RetryAfter);
    }

    [Theory]
    [InlineData("http://hooks.example.com/")] // http not enabled
    [InlineData("https://10.0.0.1/")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]
    [InlineData("https://user:pw@hooks.example.com/")]
    public async Task Invalid_urls_fail_permanently_without_sending(string url)
    {
        var stub = StubHandler.Status(HttpStatusCode.OK);
        var harness = SenderHarness.WithStub(_time, stub);

        var result = await harness.Sender.SendAsync(harness.Endpoint(new Uri(url)), SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Permanent, result.Outcome);
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task Attempt_times_out_using_the_time_provider()
    {
        var harness = SenderHarness.WithStub(_time, new StubHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));

        var send = harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), _ct);
        while (harness.Handler is StubHandler { Requests.IsEmpty: true })
        {
            await Task.Yield();
        }

        _time.Advance(harness.Options.AttemptTimeout);
        var result = await send;

        Assert.Equal(AttemptOutcome.Retryable, result.Outcome);
        Assert.Equal("The request timed out.", result.Error);
        Assert.Equal(harness.Options.AttemptTimeout, result.Duration);
    }

    [Fact]
    public async Task Caller_cancellation_is_propagated()
    {
        using var cts = new CancellationTokenSource();
        var harness = SenderHarness.WithStub(_time, new StubHandler(async (_, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), cts.Token));
    }

    [Fact]
    public async Task Network_errors_are_retryable_and_sanitized()
    {
        var harness = SenderHarness.WithStub(_time, new StubHandler((_, _) =>
            throw new HttpRequestException(HttpRequestError.ConnectionError, "Connection refused (10.20.30.40:443)")));

        var result = await harness.Sender.SendAsync(harness.Endpoint(), SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Retryable, result.Outcome);
        Assert.Equal("The request failed: ConnectionError.", result.Error);
    }

    [Fact]
    public async Task Undecryptable_secret_is_retryable_and_nothing_is_sent()
    {
        var stub = StubHandler.Status(HttpStatusCode.OK);
        var harness = SenderHarness.WithStub(_time, stub);
        var endpoint = harness.Endpoint() with { Id = "ep_other" }; // ciphertext bound to "ep_1"

        var result = await harness.Sender.SendAsync(endpoint, SenderHarness.Message(), _ct);

        Assert.Equal(AttemptOutcome.Retryable, result.Outcome);
        Assert.Empty(stub.Requests);
    }
}
