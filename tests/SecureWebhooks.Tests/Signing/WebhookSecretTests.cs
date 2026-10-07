using SecureWebhooks.Signing;

namespace SecureWebhooks.Tests.Signing;

public sealed class WebhookSecretTests
{
    [Fact]
    public void Generate_produces_32_random_bytes_by_default()
    {
        var a = WebhookSecret.Generate();
        var b = WebhookSecret.Generate();

        Assert.Equal(32, a.Key.Length);
        Assert.False(a.Key.SequenceEqual(b.Key));
    }

    [Fact]
    public void Format_and_Parse_round_trip()
    {
        var secret = WebhookSecret.Generate(64);

        var formatted = secret.Format();

        Assert.StartsWith("whsec_", formatted, StringComparison.Ordinal);
        Assert.True(WebhookSecret.Parse(formatted).Key.SequenceEqual(secret.Key));
    }

    [Fact]
    public void ToString_is_redacted()
    {
        var secret = WebhookSecret.Parse(SpecVectors.Secret);

        Assert.Equal("whsec_***", secret.ToString());
    }

    [Theory]
    [InlineData("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")] // no prefix (official libraries accept this)
    [InlineData("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")]
    [InlineData("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr")] // unpadded, needs "=="
    [InlineData("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr==")]
    public void Parse_accepts_spec_forms(string value) => Assert.True(WebhookSecret.TryParse(value, out _));

    [Fact]
    public void Unpadded_and_padded_forms_decode_to_the_same_key() =>
        Assert.True(WebhookSecret.Parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr").Key
            .SequenceEqual(WebhookSecret.Parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr==").Key));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("whsec_")]
    [InlineData("whsec_not base64!")]
    [InlineData("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS")] // 23 bytes: below the spec minimum of 24
    public void Parse_rejects_invalid_values(string? value) => Assert.False(WebhookSecret.TryParse(value, out _));

    [Fact]
    public void Parse_rejects_keys_longer_than_64_bytes() =>
        Assert.False(WebhookSecret.TryParse("whsec_" + Convert.ToBase64String(new byte[65]), out _));

    [Theory]
    [InlineData(23)]
    [InlineData(65)]
    public void FromBytes_and_Generate_reject_out_of_range_lengths(int length)
    {
        Assert.Throws<ArgumentException>(() => WebhookSecret.FromBytes(new byte[length]));
        Assert.Throws<ArgumentOutOfRangeException>(() => WebhookSecret.Generate(length));
    }
}
