using System.Buffers.Binary;
using System.Net;

namespace SecureWebhooks.Outbound;

/// <summary>Decides whether an IP address is a public, globally routable webhook destination. Allocation-free.</summary>
/// <remarks>
/// <para>Evaluation order: <c>deniedNetworks</c>, then <c>allowedNetworks</c>, then the built-in rules.</para>
/// <para>IPv4: every IANA special-purpose range used for private, loopback, link-local (incl. cloud metadata 169.254.169.254),
/// shared, benchmarking, documentation, multicast and reserved addresses is denied.</para>
/// <para>IPv4 embedded in IPv6 (IPv4-mapped <c>::ffff:0:0/96</c>, NAT64 <c>64:ff9b::/96</c>, 6to4 <c>2002::/16</c>) is extracted and
/// evaluated as IPv4. Other IPv6 is allowed only inside global unicast <c>2000::/3</c>, minus <c>2001::/23</c> (IETF protocol
/// assignments, which contains Teredo <c>2001::/32</c>), <c>2001:db8::/32</c> and <c>3fff::/20</c> (documentation). Teredo is denied
/// rather than decoded: its client address is obfuscated and the protocol is obsolete.</para>
/// </remarks>
public sealed class IpAddressPolicy
{
    private static readonly NetworkSet DefaultDenied = new(
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "3fff::/20",
    ]);

    private static readonly UInt128 Ipv4MappedPrefix = new(0, 0x0000_ffff_0000_0000);
    private static readonly UInt128 Nat64Prefix = new(0x0064_ff9b_0000_0000, 0);

    private readonly NetworkSet _allowed;
    private readonly NetworkSet _denied;

    /// <summary>Creates a policy.</summary>
    /// <param name="allowedNetworks">Escape hatch that overrides the built-in rules (e.g. loopback in tests, a private VPC peer).</param>
    /// <param name="deniedNetworks">Additional networks to deny; these take precedence over <paramref name="allowedNetworks"/>.</param>
    public IpAddressPolicy(IEnumerable<IPNetwork>? allowedNetworks = null, IEnumerable<IPNetwork>? deniedNetworks = null)
    {
        _allowed = new NetworkSet(allowedNetworks ?? []);
        _denied = new NetworkSet(deniedNetworks ?? []);
    }

    /// <summary>Returns <see langword="true"/> if a webhook may be delivered to <paramref name="address"/>.</summary>
    public bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out int length))
        {
            return false;
        }

        return length == 4
            ? IsAllowed(BinaryPrimitives.ReadUInt32BigEndian(bytes))
            : IsAllowed(BinaryPrimitives.ReadUInt128BigEndian(bytes));
    }

    private bool IsAllowed(uint ipv4) =>
        !_denied.Contains(ipv4) && (_allowed.Contains(ipv4) || !DefaultDenied.Contains(ipv4));

    private bool IsAllowed(UInt128 ipv6)
    {
        if (_denied.Contains(ipv6))
        {
            return false;
        }

        if (_allowed.Contains(ipv6))
        {
            return true;
        }

        if (ipv6 >> 32 == Ipv4MappedPrefix >> 32 || ipv6 >> 32 == Nat64Prefix >> 32)
        {
            return IsAllowed((uint)ipv6);
        }

        if (ipv6 >> 112 == 0x2002)
        {
            return IsAllowed((uint)(ipv6 >> 80));
        }

        return ipv6 >> 125 == 1 && !DefaultDenied.Contains(ipv6);
    }

    /// <summary>Precomputed (prefix, mask) pairs; lookups are a linear scan of a handful of integers.</summary>
    private sealed class NetworkSet
    {
        private readonly (uint Prefix, uint Mask)[] _v4;
        private readonly (UInt128 Prefix, UInt128 Mask)[] _v6;

        public NetworkSet(string[] networks)
            : this(Array.ConvertAll(networks, IPNetwork.Parse))
        {
        }

        public NetworkSet(IEnumerable<IPNetwork> networks)
        {
            var v4 = new List<(uint, uint)>();
            var v6 = new List<(UInt128, UInt128)>();
            Span<byte> bytes = stackalloc byte[16];
            foreach (var network in networks)
            {
                network.BaseAddress.TryWriteBytes(bytes, out int length);
                if (length == 4)
                {
                    uint mask = network.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - network.PrefixLength);
                    v4.Add((BinaryPrimitives.ReadUInt32BigEndian(bytes) & mask, mask));
                }
                else
                {
                    var mask = network.PrefixLength == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - network.PrefixLength);
                    v6.Add((BinaryPrimitives.ReadUInt128BigEndian(bytes) & mask, mask));
                }
            }

            _v4 = [.. v4];
            _v6 = [.. v6];
        }

        public bool Contains(uint address)
        {
            foreach (var (prefix, mask) in _v4)
            {
                if ((address & mask) == prefix)
                {
                    return true;
                }
            }

            return false;
        }

        public bool Contains(UInt128 address)
        {
            foreach (var (prefix, mask) in _v6)
            {
                if ((address & mask) == prefix)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
