using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SecureWebhooks.Outbound;

/// <summary>
/// A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves the host, rejects the request if any resolved
/// address is disallowed, and connects the socket directly to a validated address. Because the socket never connects
/// to anything that was not checked, a DNS answer that changes between validation and connect (DNS rebinding) has no effect.
/// TLS and SNI still use the original host name: <see cref="SocketsHttpHandler"/> layers TLS on top of the returned stream.
/// </summary>
public sealed class SsrfSafeConnectCallback
{
    private readonly IpAddressPolicy _policy;
    private readonly IDnsResolver _dns;
    private readonly ILogger _logger;

    /// <summary>Creates the callback.</summary>
    public SsrfSafeConnectCallback(IpAddressPolicy policy, ILogger<SsrfSafeConnectCallback>? logger = null)
        : this(policy, SystemDnsResolver.Instance, logger)
    {
    }

    internal SsrfSafeConnectCallback(IpAddressPolicy policy, IDnsResolver dns, ILogger? logger)
    {
        _policy = policy;
        _dns = dns;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates a <see cref="SocketsHttpHandler"/> that uses this callback and the hardened settings below.
    /// <list type="bullet">
    /// <item><c>UseProxy = false</c>: with a proxy, the callback would validate the proxy instead of the destination.</item>
    /// <item><c>AllowAutoRedirect = false</c>: a redirect could point at an internal URL; 3xx is reported as a failed attempt.</item>
    /// <item><c>UseCookies = false</c>: endpoints must not be able to set state shared across tenants.</item>
    /// <item><c>AutomaticDecompression = None</c>: avoids decompression bombs; the body is only sampled for diagnostics anyway.</item>
    /// <item><c>MaxResponseHeadersLength</c>, <c>ConnectTimeout</c>, <c>MaxConnectionsPerServer</c>: bound the resources a hostile endpoint can consume.</item>
    /// <item><c>PooledConnectionLifetime</c>: connections are recycled so DNS is periodically re-resolved and re-validated.</item>
    /// </list>
    /// </summary>
    public SocketsHttpHandler CreateHandler(WebhookSendingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new SocketsHttpHandler
        {
            ConnectCallback = ConnectAsync,
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = options.MaxResponseHeadersLength,
            ConnectTimeout = options.ConnectTimeout,
            PooledConnectionLifetime = options.PooledConnectionLifetime,
            MaxConnectionsPerServer = options.MaxConnectionsPerServer,
        };
    }

    /// <summary>Resolves, validates and connects. Throws <see cref="SsrfBlockedException"/> if any address is disallowed.</summary>
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var (host, port) = (context.DnsEndPoint.Host, context.DnsEndPoint.Port);

        IPAddress[] addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await _dns.ResolveAsync(host, cancellationToken).ConfigureAwait(false);

        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        // Reject if ANY address is disallowed rather than filtering: a host that mixes public and internal
        // records is either misconfigured or an attack, and filtering would make behaviour depend on record order.
        foreach (var address in addresses)
        {
            if (!_policy.IsAllowed(address))
            {
                Log.SsrfBlocked(_logger, host, port, address);
                OutboundTelemetry.SsrfBlocked.Add(1);
                throw new SsrfBlockedException();
            }
        }

        Exception? lastError = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw lastError!;
    }
}
