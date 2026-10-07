namespace SecureWebhooks.Tests.Signing;

/// <summary>
/// Test vectors from the official standard-webhooks/standard-webhooks repository
/// (libraries/python/tests/test_webhooks.py, libraries/csharp/StandardWebhooks.Tests/WebhookTest.cs, libraries/go/webhook_test.go).
/// </summary>
internal static class SpecVectors
{
    public const string Secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    public const string MessageId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    public const long Timestamp = 1614265330;
    public const string Payload = "{\"test\": 2432232314}";
    public const string ExpectedSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    // "test_invalid_signature_raises_error": differs from the valid signature in the last base64 character.
    public const string InvalidSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=";

    // "test_multi_sig_payload_is_valid": decoys around the valid signature, including an unknown "v2" version.
    public const string DecoySignature = "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=";
    public const string DecoyV2Signature = "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=";
}
