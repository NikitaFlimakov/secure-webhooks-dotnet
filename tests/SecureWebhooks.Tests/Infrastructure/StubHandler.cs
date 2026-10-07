using System.Collections.Concurrent;
using System.Net;

namespace SecureWebhooks.Tests.Infrastructure;

/// <summary>An in-process HttpMessageHandler that records requests and returns scripted responses.</summary>
internal sealed class StubHandler(Func<CapturedRequest, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public ConcurrentQueue<CapturedRequest> Requests { get; } = new();

    public static StubHandler Status(HttpStatusCode status) => new((_, _) => Task.FromResult(new HttpResponseMessage(status)));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var captured = new CapturedRequest(
            request.RequestUri!,
            request.Headers.NonValidated.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase),
            request.Content?.Headers.ContentType?.ToString(),
            body);
        Requests.Enqueue(captured);
        return await respond(captured, cancellationToken);
    }
}

internal sealed record CapturedRequest(Uri Url, Dictionary<string, string> Headers, string? ContentType, byte[] Body);

internal sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
}
