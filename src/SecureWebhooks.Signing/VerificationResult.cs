namespace SecureWebhooks.Signing;

/// <summary>Outcome of <see cref="WebhookVerifier.Verify(ReadOnlySpan{byte}, ReadOnlySpan{char}, ReadOnlySpan{char}, ReadOnlySpan{char}, ReadOnlySpan{WebhookSecret}, TimeProvider, TimeSpan)"/>.</summary>
public enum VerificationResult
{
    /// <summary>At least one signature matched and the timestamp is within tolerance.</summary>
    Valid,

    /// <summary>The id, timestamp or signature header is missing or empty.</summary>
    MissingHeader,

    /// <summary>The timestamp is not a non-negative integer.</summary>
    MalformedTimestamp,

    /// <summary>The timestamp is older than the tolerance allows (possible replay).</summary>
    TimestampTooOld,

    /// <summary>The timestamp is further in the future than the tolerance allows.</summary>
    TimestampTooNew,

    /// <summary>The signature header is oversized, has too many entries, or a <c>v1</c> entry is not a valid 32-byte base64 value.</summary>
    MalformedSignature,

    /// <summary>No <c>v1</c> signature matched any of the secrets.</summary>
    NoMatchingSignature,
}
