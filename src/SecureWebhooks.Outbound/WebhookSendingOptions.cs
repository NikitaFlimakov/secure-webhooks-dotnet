using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace SecureWebhooks.Outbound;

/// <summary>Options for SSRF protection and the hardened HTTP handler.</summary>
[UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "The attributes are only read at compile time by the [OptionsValidator] source generator, which emits trimming-safe copies.")]
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
    [Range(typeof(TimeSpan), "00:00:01", "00:01:00")]
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum lifetime of a pooled connection. Bounds how long a DNS answer (and its validation) is reused.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "01:00:00")]
    public TimeSpan PooledConnectionLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Maximum concurrent connections per destination.</summary>
    [Range(1, 1000)]
    public int MaxConnectionsPerServer { get; set; } = 20;

    /// <summary>Maximum total size of response headers, in kilobytes.</summary>
    [Range(1, 64)]
    public int MaxResponseHeadersLength { get; set; } = 16;

    /// <summary>Timeout for a single attempt, from connect until the response body preview has been read.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:05:00")]
    public TimeSpan AttemptTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>At most this many bytes of the response body are read (for diagnostics); the rest is discarded.</summary>
    [Range(0, 1024 * 1024)]
    public int MaxResponseBodyBytes { get; set; } = 4096;
}
