using System.Net;
using SecureWebhooks.Outbound;
using SecureWebhooks.Tests.Infrastructure;

namespace SecureWebhooks.Tests.Ssrf;

/// <summary>End-to-end through a real SocketsHttpHandler and a real Kestrel server on loopback.</summary>
public sealed class SsrfIntegrationTests : IAsyncLifetime
{
    private static readonly IPAddress MetadataAddress = IPAddress.Parse("169.254.169.254");
    private LoopbackServer _server = null!;

    public async ValueTask InitializeAsync() => _server = await LoopbackServer.StartAsync();

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();

    private static HttpClient CreateClient(IDnsResolver? dns = null, params string[] allowedNetworks)
    {
        var options = new WebhookSendingOptions();
        foreach (var network in allowedNetworks)
        {
            options.AllowedNetworks.Add(IPNetwork.Parse(network));
        }

        var callback = new SsrfSafeConnectCallback(new IpAddressPolicy(options.AllowedNetworks), dns ?? SystemDnsResolver.Instance, null);
        return new HttpClient(callback.CreateHandler(options));
    }

    private Uri HostUrl(string host, string path = "/") => new($"http://{host}:{_server.Port}{path}");

    private static async Task AssertBlockedAsync(Task task)
    {
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => task);
        Assert.IsType<SsrfBlockedException>(ex.InnerException);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")] // resolved by the real OS resolver
    [InlineData("[::ffff:127.0.0.1]")]
    public async Task Loopback_is_blocked_by_default(string host)
    {
        using var client = CreateClient();

        await AssertBlockedAsync(client.GetAsync(HostUrl(host), TestContext.Current.CancellationToken));
        Assert.Empty(_server.Requests);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")] // may resolve to ::1 first; the callback falls through to 127.0.0.1
    public async Task Loopback_is_reachable_when_explicitly_allowed(string host)
    {
        using var client = CreateClient(null, "127.0.0.0/8", "::1/128");

        using var response = await client.GetAsync(HostUrl(host), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_server.Requests);
    }

    [Fact]
    public async Task Host_resolving_to_cloud_metadata_is_blocked()
    {
        using var client = CreateClient(new FakeDnsResolver([MetadataAddress]));

        await AssertBlockedAsync(client.GetAsync(HostUrl("hooks.example.com"), TestContext.Current.CancellationToken));
        Assert.Empty(_server.Requests);
    }

    [Fact]
    public async Task Any_disallowed_address_rejects_the_whole_host()
    {
        // The first record is allowed and reachable, but the host also resolves to an internal address.
        using var client = CreateClient(new FakeDnsResolver([IPAddress.Loopback, IPAddress.Parse("10.0.0.1")]), "127.0.0.1/32");

        await AssertBlockedAsync(client.GetAsync(HostUrl("mixed.example.com"), TestContext.Current.CancellationToken));
        Assert.Empty(_server.Requests);
    }

    [Fact]
    public async Task Socket_connects_to_the_validated_address_and_keeps_the_original_host()
    {
        var dns = new FakeDnsResolver([IPAddress.Loopback]);
        using var client = CreateClient(dns, "127.0.0.1/32");

        using var response = await client.GetAsync(HostUrl("hooks.example.com"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"hooks.example.com:{_server.Port}", Assert.Single(_server.Requests).Host);
        Assert.Equal(1, dns.Lookups);
    }

    [Fact]
    public async Task Dns_rebinding_to_an_internal_address_is_blocked_on_the_next_connection()
    {
        // First answer passes validation; the attacker then flips the record to the metadata service.
        var dns = new FakeDnsResolver([IPAddress.Loopback], [MetadataAddress]);
        using var client = CreateClient(dns, "127.0.0.1/32");

        using (var first = new HttpRequestMessage(HttpMethod.Get, HostUrl("rebind.example.com")))
        {
            first.Headers.ConnectionClose = true; // force a fresh connection (and DNS lookup) for the next request
            using var response = await client.SendAsync(first, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        await AssertBlockedAsync(client.GetAsync(HostUrl("rebind.example.com"), TestContext.Current.CancellationToken));
        Assert.Equal(2, dns.Lookups);
        Assert.Single(_server.Requests);
    }

    [Fact]
    public async Task Redirects_are_not_followed()
    {
        using var client = CreateClient(null, "127.0.0.0/8");

        using var response = await client.GetAsync(_server.Url("/redirect"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Single(_server.Requests);
    }

    [Fact]
    public void Handler_is_hardened()
    {
        var options = new WebhookSendingOptions();
        using var handler = new SsrfSafeConnectCallback(new IpAddressPolicy()).CreateHandler(options);

        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(options.ConnectTimeout, handler.ConnectTimeout);
        Assert.Equal(options.PooledConnectionLifetime, handler.PooledConnectionLifetime);
        Assert.Equal(options.MaxResponseHeadersLength, handler.MaxResponseHeadersLength);
        Assert.Equal(options.MaxConnectionsPerServer, handler.MaxConnectionsPerServer);
        Assert.NotNull(handler.ConnectCallback);
    }
}
