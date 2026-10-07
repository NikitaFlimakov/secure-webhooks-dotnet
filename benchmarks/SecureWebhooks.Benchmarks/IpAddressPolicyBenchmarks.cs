using System.Net;
using BenchmarkDotNet.Attributes;
using SecureWebhooks.Outbound;

namespace SecureWebhooks.Benchmarks;

/// <summary>
/// IpAddressPolicy (masked integer compare over precomputed prefixes) vs. a straightforward loop over
/// System.Net.IPNetwork.Contains with the same IPv4 deny list.
/// </summary>
[MemoryDiagnoser]
public class IpAddressPolicyBenchmarks
{
    private static readonly IPNetwork[] NaiveDenyList = Array.ConvertAll(
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4",
    ], IPNetwork.Parse);

    private readonly IpAddressPolicy _policy = new();
    private IPAddress _address = null!;

    [Params("8.8.8.8", "192.168.1.1", "2606:4700:4700::1111", "::ffff:169.254.169.254")]
    public string Address { get; set; } = "";

    [GlobalSetup]
    public void Setup() => _address = IPAddress.Parse(Address);

    [Benchmark(Baseline = true, Description = "IPNetwork.Contains loop (IPv4 only)")]
    public bool NaiveIPNetwork()
    {
        var address = _address.IsIPv4MappedToIPv6 ? _address.MapToIPv4() : _address;
        foreach (var network in NaiveDenyList)
        {
            if (network.Contains(address))
            {
                return false;
            }
        }

        return true;
    }

    [Benchmark(Description = "IpAddressPolicy.IsAllowed")]
    public bool Policy() => _policy.IsAllowed(_address);
}
