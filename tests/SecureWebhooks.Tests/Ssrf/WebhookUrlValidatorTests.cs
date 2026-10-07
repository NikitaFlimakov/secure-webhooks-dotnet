using SecureWebhooks.Outbound;

namespace SecureWebhooks.Tests.Ssrf;

public sealed class WebhookUrlValidatorTests
{
    private static WebhookUrlValidator Create(Action<WebhookSendingOptions>? configure = null)
    {
        var options = new WebhookSendingOptions();
        configure?.Invoke(options);
        return new WebhookUrlValidator(new IpAddressPolicy(options.AllowedNetworks, options.DeniedNetworks), options);
    }

    [Theory]
    [InlineData("https://example.com/webhooks")]
    [InlineData("https://example.com:8443/hooks?token=abc")]
    [InlineData("https://8.8.8.8/")]
    [InlineData("https://[2606:4700:4700::1111]/")]
    public void Accepts_public_https_urls(string url) => Assert.True(Create().Validate(new Uri(url)).IsValid);

    [Theory]
    [InlineData("http://example.com/")] // http is opt-in
    [InlineData("ftp://example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("https://user:pass@example.com/")] // userinfo
    [InlineData("https://localhost/")]
    [InlineData("https://LOCALHOST./")]
    [InlineData("https://api.localhost/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]
    [InlineData("https://10.1.2.3/")]
    [InlineData("https://2130706433/")] // decimal 127.0.0.1
    [InlineData("https://0x7f.0.0.1/")] // hex
    [InlineData("https://017700000001/")] // octal
    [InlineData("https://0177.0.0.1/")]
    [InlineData("https://127.1/")]
    [InlineData("https://[::1]/")]
    [InlineData("https://[::ffff:127.0.0.1]/")]
    [InlineData("https://[::ffff:169.254.169.254]/")]
    [InlineData("https://[fe80::1]/")]
    public void Rejects_unsafe_urls(string url)
    {
        var result = Create().Validate(new Uri(url));

        Assert.False(result.IsValid);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Rejects_relative_and_null_urls()
    {
        Assert.False(Create().Validate(new Uri("/hooks", UriKind.Relative)).IsValid);
        Assert.False(Create().Validate(null).IsValid);
    }

    [Fact]
    public void Http_is_accepted_only_when_enabled() =>
        Assert.True(Create(o => o.AllowHttp = true).Validate(new Uri("http://example.com/")).IsValid);

    [Fact]
    public void Allowed_ports_restrict_destinations_when_configured()
    {
        var validator = Create(o => o.AllowedPorts.Add(443));

        Assert.True(validator.Validate(new Uri("https://example.com/")).IsValid);
        Assert.False(validator.Validate(new Uri("https://example.com:6379/")).IsValid);
    }

    [Fact]
    public void Error_messages_do_not_echo_the_address()
    {
        var result = Create().Validate(new Uri("https://10.1.2.3/"));

        Assert.DoesNotContain("10.1.2.3", result.Error, StringComparison.Ordinal);
    }
}
