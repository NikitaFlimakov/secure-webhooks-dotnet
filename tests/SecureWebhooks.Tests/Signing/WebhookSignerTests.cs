using System.Security.Cryptography;
using System.Text;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Tests.Signing;

public sealed class WebhookSignerTests
{
    private static readonly DateTimeOffset SpecTime = DateTimeOffset.FromUnixTimeSeconds(SpecVectors.Timestamp);

    [Fact]
    public void Sign_matches_official_spec_vector()
    {
        var signature = WebhookSigner.Sign(
            SpecVectors.MessageId, SpecTime, Encoding.UTF8.GetBytes(SpecVectors.Payload), [WebhookSecret.Parse(SpecVectors.Secret)]);

        Assert.Equal(SpecVectors.ExpectedSignature, signature);
    }

    [Fact]
    public void Sign_truncates_timestamp_to_whole_seconds()
    {
        var signature = WebhookSigner.Sign(
            SpecVectors.MessageId, SpecTime.AddMilliseconds(999), Encoding.UTF8.GetBytes(SpecVectors.Payload), [WebhookSecret.Parse(SpecVectors.Secret)]);

        Assert.Equal(SpecVectors.ExpectedSignature, signature);
    }

    [Fact]
    public void Sign_with_several_secrets_emits_space_delimited_signatures_in_order()
    {
        var current = WebhookSecret.Generate();
        var previous = WebhookSecret.Parse(SpecVectors.Secret);

        var header = WebhookSigner.Sign(SpecVectors.MessageId, SpecTime, Encoding.UTF8.GetBytes(SpecVectors.Payload), [current, previous]);

        var parts = header.Split(' ');
        Assert.Equal(2, parts.Length);
        Assert.Equal(ReferenceSign(current, SpecVectors.MessageId, SpecVectors.Timestamp, Encoding.UTF8.GetBytes(SpecVectors.Payload)), parts[0]);
        Assert.Equal(SpecVectors.ExpectedSignature, parts[1]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{\"emoji\":\"🦀\",\"text\":\"Привет, 世界\"}")]
    [InlineData("{\"a\":1}")]
    public void Sign_matches_a_naive_reference_implementation(string payload)
    {
        var secret = WebhookSecret.Generate();
        var bytes = Encoding.UTF8.GetBytes(payload);

        var signature = WebhookSigner.Sign("msg_ünïcode", SpecTime, bytes, [secret]);

        Assert.Equal(ReferenceSign(secret, "msg_ünïcode", SpecVectors.Timestamp, bytes), signature);
    }

    [Fact]
    public void Sign_handles_payloads_larger_than_the_pooled_buffer_threshold()
    {
        var secret = WebhookSecret.Generate();
        var bytes = RandomNumberGenerator.GetBytes(300 * 1024);

        Assert.Equal(ReferenceSign(secret, "msg_1", SpecVectors.Timestamp, bytes), WebhookSigner.Sign("msg_1", SpecTime, bytes, [secret]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("msg.1")]
    public void Sign_rejects_invalid_message_ids(string messageId) =>
        Assert.ThrowsAny<ArgumentException>(() => WebhookSigner.Sign(messageId, SpecTime, [], [WebhookSecret.Generate()]));

    [Fact]
    public void Sign_requires_at_least_one_and_at_most_16_secrets()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WebhookSigner.Sign("msg_1", SpecTime, [], []));
        var many = Enumerable.Range(0, 17).Select(_ => WebhookSecret.Generate()).ToArray();
        Assert.Throws<ArgumentOutOfRangeException>(() => WebhookSigner.Sign("msg_1", SpecTime, [], many));
    }

    // Deliberately simple: builds the signed content as a string, as the specification describes it.
    internal static string ReferenceSign(WebhookSecret secret, string id, long timestamp, byte[] payload)
    {
        var content = Encoding.UTF8.GetBytes($"{id}.{timestamp}.").Concat(payload).ToArray();
        return "v1," + Convert.ToBase64String(HMACSHA256.HashData(secret.Key.ToArray(), content));
    }
}
