using System.Net;

namespace SecureWebhooks.Outbound;

/// <summary>Options for SSRF protection and the hardened HTTP handler.</summary>
public sealed class WebhookSendingOptions
{
    /// <summary>Allow <c>http://</c> endpoints. Off by default; intended for local development only.</summary>
    public bool AllowHttp { get; set; }

    /// <summary>If non-empty, only these destination ports are accepted. Empty (the default) means any port.</summary>
    public IList<int> AllowedPorts { get; } = [];

    /// <summary>Networks that override the built-in deny rules (e.g. <c>127.0.0.0/8</c> in tests). See <see cref="IpAddressPolicy"/>.</summary>
    public IList<IPNetwork> AllowedNetworks { get; } = [];

    /// <summary>Additional networks to deny; these win over <see cref="AllowedNetworks"/>.</summary>
    public IList<IPNetwork> DeniedNetworks { get; } = [];

    /// <summary>TCP connect timeout (including DNS resolution and validation).</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum lifetime of a pooled connection. Bounds how long a DNS answer (and its validation) is reused.</summary>
    public TimeSpan PooledConnectionLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Maximum concurrent connections per destination.</summary>
    public int MaxConnectionsPerServer { get; set; } = 20;

    /// <summary>Maximum total size of response headers, in kilobytes.</summary>
    public int MaxResponseHeadersLength { get; set; } = 16;

    /// <summary>Timeout for a single attempt, from connect until the response body preview has been read.</summary>
    public TimeSpan AttemptTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>At most this many bytes of the response body are read (for diagnostics); the rest is discarded.</summary>
    public int MaxResponseBodyBytes { get; set; } = 4096;
}
