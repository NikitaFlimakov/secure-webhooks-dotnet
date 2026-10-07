using System.Text;
using Microsoft.Extensions.Time.Testing;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Tests.Signing;

public sealed class WebhookVerifierTests
{
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes(SpecVectors.Payload);
    private static readonly WebhookSecret[] Secrets = [WebhookSecret.Parse(SpecVectors.Secret)];
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(SpecVectors.Timestamp));

    private VerificationResult Verify(
        string signature = SpecVectors.ExpectedSignature,
        string id = SpecVectors.MessageId,
        string timestamp = "1614265330",
        byte[]? payload = null,
        WebhookSecret[]? secrets = null) =>
        WebhookVerifier.Verify(payload ?? Payload, id, timestamp, signature, secrets ?? Secrets, _time);

    [Fact]
    public void Official_spec_vector_is_valid() => Assert.Equal(VerificationResult.Valid, Verify());

    [Fact]
    public void Official_invalid_signature_vector_does_not_match() =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(SpecVectors.InvalidSignature));

    [Fact]
    public void Official_multi_signature_vector_is_valid() =>
        Assert.Equal(VerificationResult.Valid, Verify(string.Join(' ',
            SpecVectors.DecoySignature, SpecVectors.DecoyV2Signature, SpecVectors.ExpectedSignature, SpecVectors.DecoySignature)));

    [Fact]
    public void Tampered_payload_is_rejected() =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(payload: Encoding.UTF8.GetBytes("{\"test\": 2432232315}")));

    [Fact]
    public void Tampered_message_id_is_rejected() =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(id: "msg_p5jXN8AQM9LWM0D4loKWxJel"));

    [Fact]
    public void Tampered_timestamp_within_tolerance_is_rejected() =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(timestamp: "1614265331"));

    [Theory]
    [InlineData(-300, VerificationResult.Valid)]
    [InlineData(-301, VerificationResult.TimestampTooOld)]
    [InlineData(300, VerificationResult.Valid)]
    [InlineData(301, VerificationResult.TimestampTooNew)]
    public void Tolerance_is_inclusive_in_both_directions(int messageAgeOffsetSeconds, VerificationResult expected)
    {
        var sentAt = _time.GetUtcNow().AddSeconds(messageAgeOffsetSeconds);
        var header = WebhookSigner.Sign(SpecVectors.MessageId, sentAt, Payload, Secrets);

        Assert.Equal(expected, Verify(header, timestamp: sentAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    [Fact]
    public void Custom_tolerance_is_respected()
    {
        _time.Advance(TimeSpan.FromSeconds(31));

        Assert.Equal(VerificationResult.TimestampTooOld, WebhookVerifier.Verify(
            Payload, SpecVectors.MessageId, "1614265330", SpecVectors.ExpectedSignature, Secrets, _time, TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void Rotation_old_secret_still_verifies_while_both_are_signed()
    {
        var oldSecret = WebhookSecret.Generate();
        var newSecret = WebhookSecret.Generate();
        var header = WebhookSigner.Sign(SpecVectors.MessageId, _time.GetUtcNow(), Payload, [newSecret, oldSecret]);

        Assert.Equal(VerificationResult.Valid, Verify(header, secrets: [oldSecret]));
        Assert.Equal(VerificationResult.Valid, Verify(header, secrets: [newSecret]));
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(header, secrets: [WebhookSecret.Generate()]));
    }

    [Fact]
    public void Receiver_can_accept_old_and_new_secret_during_rotation()
    {
        var oldSecret = WebhookSecret.Generate();
        var newSecret = WebhookSecret.Generate();
        var header = WebhookSigner.Sign(SpecVectors.MessageId, _time.GetUtcNow(), Payload, [newSecret]);

        Assert.Equal(VerificationResult.Valid, Verify(header, secrets: [oldSecret, newSecret]));
    }

    [Theory]
    [InlineData("", "1614265330", SpecVectors.ExpectedSignature)]
    [InlineData(SpecVectors.MessageId, "", SpecVectors.ExpectedSignature)]
    [InlineData(SpecVectors.MessageId, "1614265330", "")]
    public void Missing_headers_are_reported(string id, string timestamp, string signature) =>
        Assert.Equal(VerificationResult.MissingHeader, Verify(signature, id, timestamp));

    [Theory]
    [InlineData("hello")]
    [InlineData("-1614265330")]
    [InlineData("+1614265330")]
    [InlineData(" 1614265330")]
    [InlineData("1614265330.5")]
    [InlineData("99999999999999999999999")]
    public void Malformed_timestamps_are_reported(string timestamp) =>
        Assert.Equal(VerificationResult.MalformedTimestamp, Verify(timestamp: timestamp));

    [Theory]
    [InlineData("v1,")]
    [InlineData("v1,not-base64")]
    [InlineData("v1,AAAA")] // valid base64, wrong length
    public void Malformed_v1_signatures_are_reported(string signature) =>
        Assert.Equal(VerificationResult.MalformedSignature, Verify(signature));

    [Fact]
    public void Malformed_entry_does_not_hide_a_valid_one() =>
        Assert.Equal(VerificationResult.Valid, Verify("v1,garbage " + SpecVectors.ExpectedSignature));

    [Theory]
    [InlineData("v1a,hnO3f9T8Ytu9HwrXslvumlUpqtNVqkhqw/enGzPCXe5BdqzCInXqYXFymVJaA7AZdpXwVLPo3mNl8EM+m7TBAg==")]
    [InlineData("garbage")]
    public void Unknown_versions_are_ignored(string signature) =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(signature));

    [Fact]
    public void Oversized_signature_header_is_rejected_before_parsing()
    {
        var header = SpecVectors.ExpectedSignature + " " + new string('x', WebhookVerifier.MaxSignatureHeaderLength);

        Assert.Equal(VerificationResult.MalformedSignature, Verify(header));
    }

    [Fact]
    public void Too_many_signatures_are_rejected()
    {
        var header = string.Join(' ', Enumerable.Repeat(SpecVectors.DecoySignature, WebhookVerifier.MaxSignatures)) + " " + SpecVectors.ExpectedSignature;

        Assert.Equal(VerificationResult.MalformedSignature, Verify(header));
    }

    [Fact]
    public void Extra_spaces_between_signatures_are_tolerated() =>
        Assert.Equal(VerificationResult.Valid, Verify("  " + SpecVectors.DecoySignature + "   " + SpecVectors.ExpectedSignature + " "));

    [Theory]
    [InlineData("")]
    [InlineData("{\"emoji\":\"🦀\",\"text\":\"Привет, 世界\"}")]
    public void Empty_and_unicode_payloads_round_trip(string payload)
    {
        var bytes = Encoding.UTF8.GetBytes(payload);
        var header = WebhookSigner.Sign("msg_1", _time.GetUtcNow(), bytes, Secrets);

        Assert.Equal(VerificationResult.Valid, Verify(header, "msg_1", "1614265330", bytes));
    }

    [Fact]
    public void No_secrets_never_validates() =>
        Assert.Equal(VerificationResult.NoMatchingSignature, Verify(secrets: []));
}
