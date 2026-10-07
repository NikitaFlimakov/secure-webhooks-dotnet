using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace SecureWebhooks.Tests.Infrastructure;

/// <summary>A real Kestrel server on 127.0.0.1 with an ephemeral port.</summary>
internal sealed class LoopbackServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private LoopbackServer(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public int Port { get; }

    /// <summary>Requests received, keyed by path.</summary>
    public ConcurrentQueue<RecordedRequest> Requests { get; } = new();

    public long BigBodyBytesWritten;

    public Uri Url(string path = "/") => new($"http://127.0.0.1:{Port}{path}");

    public static async Task<LoopbackServer> StartAsync(Func<HttpContext, Task>? handler = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        LoopbackServer? server = null;

        app.Run(async context =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body);
            server!.Requests.Enqueue(new RecordedRequest(
                context.Request.Path,
                context.Request.Host.Value ?? "",
                context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase),
                body.ToArray()));

            if (handler is not null)
            {
                await handler(context);
                return;
            }

            switch (context.Request.Path.Value)
            {
                case "/redirect":
                    context.Response.StatusCode = StatusCodes.Status302Found;
                    context.Response.Headers.Location = "http://169.254.169.254/latest/meta-data/";
                    break;
                case "/big":
                    // Streams up to 64 MB; a well-behaved client stops reading long before that.
                    var chunk = new byte[64 * 1024];
                    try
                    {
                        for (int i = 0; i < 1024; i++)
                        {
                            await context.Response.Body.WriteAsync(chunk, context.RequestAborted);
                            Interlocked.Add(ref server.BigBodyBytesWritten, chunk.Length);
                        }
                    }
                    catch (Exception ex) when (ex is OperationCanceledException or IOException)
                    {
                        // Client went away: expected.
                    }

                    break;
                default:
                    await context.Response.WriteAsync("ok");
                    break;
            }
        });

        await app.StartAsync();
        var port = new Uri(app.Urls.First()).Port;
        server = new LoopbackServer(app, port);
        return server;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

internal sealed record RecordedRequest(string Path, string Host, Dictionary<string, string> Headers, byte[] Body);
