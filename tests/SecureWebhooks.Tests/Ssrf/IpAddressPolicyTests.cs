using System.Net;
using SecureWebhooks.Outbound;

namespace SecureWebhooks.Tests.Ssrf;

public sealed class IpAddressPolicyTests
{
    private static readonly IpAddressPolicy Default = new();

    [Theory]
    [InlineData("0.0.0.0")] // 0.0.0.0/8 "this network" (connects to localhost on Linux)
    [InlineData("0.255.255.255")]
    [InlineData("10.0.0.1")] // 10/8 private
    [InlineData("10.255.255.255")]
    [InlineData("100.64.0.1")] // 100.64/10 shared address space (CGNAT)
    [InlineData("100.127.255.255")]
    [InlineData("127.0.0.1")] // 127/8 loopback
    [InlineData("127.255.255.254")]
    [InlineData("169.254.169.254")] // 169.254/16 link-local: AWS/GCP/Azure instance metadata
    [InlineData("169.254.0.1")]
    [InlineData("172.16.0.1")] // 172.16/12 private
    [InlineData("172.31.255.255")]
    [InlineData("192.0.0.1")] // 192.0.0/24 IETF protocol assignments
    [InlineData("192.0.2.1")] // TEST-NET-1
    [InlineData("192.88.99.1")] // 6to4 relay anycast
    [InlineData("192.168.1.1")] // 192.168/16 private
    [InlineData("198.18.0.1")] // 198.18/15 benchmarking
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.1")] // TEST-NET-2
    [InlineData("203.0.113.1")] // TEST-NET-3
    [InlineData("224.0.0.1")] // 224/4 multicast
    [InlineData("239.255.255.255")]
    [InlineData("240.0.0.1")] // 240/4 reserved
    [InlineData("255.255.255.255")] // limited broadcast
    public void Denies_ipv4_special_purpose_ranges(string address) => Assert.False(Default.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("9.255.255.255")] // just below 10/8
    [InlineData("11.0.0.0")] // just above 10/8
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("126.255.255.255")]
    [InlineData("128.0.0.0")]
    [InlineData("169.253.255.255")]
    [InlineData("169.255.0.0")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("192.0.1.0")]
    [InlineData("192.167.255.255")]
    [InlineData("192.169.0.0")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.0")]
    [InlineData("223.255.255.255")] // just below 224/4
    public void Allows_public_ipv4_including_range_boundaries(string address) => Assert.True(Default.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("::")] // unspecified
    [InlineData("::1")] // loopback
    [InlineData("::127.0.0.1")] // deprecated IPv4-compatible
    [InlineData("fc00::1")] // fc00::/7 unique local
    [InlineData("fd12:3456:789a::1")]
    [InlineData("fe80::1")] // fe80::/10 link-local
    [InlineData("febf:ffff::1")]
    [InlineData("fec0::1")] // fec0::/10 deprecated site-local
    [InlineData("ff02::1")] // ff00::/8 multicast
    [InlineData("100::1")] // 100::/64 discard-only
    [InlineData("2001:db8::1")] // documentation
    [InlineData("3fff::1")] // documentation (RFC 9637)
    [InlineData("2001::1")] // Teredo
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2")] // Teredo, RFC 4380 example
    [InlineData("2001:2::1")] // benchmarking, inside 2001::/23
    [InlineData("64:ff9b:1::1")] // local-use NAT64 (RFC 8215), outside 2000::/3
    [InlineData("4000::1")] // not global unicast
    public void Denies_ipv6_special_purpose_and_non_global_ranges(string address) => Assert.False(Default.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("::ffff:127.0.0.1")] // IPv4-mapped
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("::ffff:0.0.0.0")]
    [InlineData("64:ff9b::7f00:1")] // NAT64 of 127.0.0.1
    [InlineData("64:ff9b::a9fe:a9fe")] // NAT64 of 169.254.169.254
    [InlineData("64:ff9b::c0a8:101")] // NAT64 of 192.168.1.1
    [InlineData("2002:7f00:1::1")] // 6to4 of 127.0.0.1
    [InlineData("2002:a9fe:a9fe::1")] // 6to4 of 169.254.169.254
    [InlineData("2002:a00:1::")] // 6to4 of 10.0.0.1
    public void Denies_ipv6_forms_embedding_a_denied_ipv4(string address) => Assert.False(Default.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")] // 2001:4860:: is outside 2001::/23
    [InlineData("2a00:1450:4001::1")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("2002:808:808::1")]
    public void Allows_public_ipv6_and_embedded_public_ipv4(string address) => Assert.True(Default.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("2130706433")] // decimal
    [InlineData("0x7f.0.0.1")] // hex
    [InlineData("017700000001")] // octal
    [InlineData("127.1")] // short form
    public void Obfuscated_ipv4_literals_parse_to_loopback_and_are_denied(string literal)
    {
        Assert.True(IPAddress.TryParse(literal, out var address));
        Assert.False(Default.IsAllowed(address));
    }

    [Fact]
    public void Allowed_networks_override_built_in_rules_including_embedded_forms()
    {
        var policy = new IpAddressPolicy(allowedNetworks: [IPNetwork.Parse("127.0.0.0/8"), IPNetwork.Parse("fd00::/8")]);

        Assert.True(policy.IsAllowed(IPAddress.Parse("127.0.0.1")));
        Assert.True(policy.IsAllowed(IPAddress.Parse("::ffff:127.0.0.1")));
        Assert.True(policy.IsAllowed(IPAddress.Parse("fd00::1")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("10.0.0.1")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("::1")));
    }

    [Fact]
    public void Denied_networks_take_precedence_over_allowed_networks()
    {
        var policy = new IpAddressPolicy(
            allowedNetworks: [IPNetwork.Parse("10.0.0.0/8")],
            deniedNetworks: [IPNetwork.Parse("10.0.0.5/32"), IPNetwork.Parse("8.8.8.0/24"), IPNetwork.Parse("2606:4700::/32")]);

        Assert.True(policy.IsAllowed(IPAddress.Parse("10.0.0.4")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("10.0.0.5")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("8.8.8.8")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("::ffff:8.8.8.8")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("2606:4700:4700::1111")));
    }

    [Fact]
    public void Zero_length_prefix_matches_everything()
    {
        var policy = new IpAddressPolicy(deniedNetworks: [IPNetwork.Parse("0.0.0.0/0"), IPNetwork.Parse("::/0")]);

        Assert.False(policy.IsAllowed(IPAddress.Parse("8.8.8.8")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("2606:4700:4700::1111")));
    }
}
