using System.Net;

namespace SecureWebhooks.Outbound;

/// <summary>Test seam for DNS resolution (e.g. simulating DNS rebinding).</summary>
internal interface IDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

internal sealed class SystemDnsResolver : IDnsResolver
{
    public static readonly SystemDnsResolver Instance = new();

    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        Dns.GetHostAddressesAsync(host, cancellationToken);
}
