using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;

namespace SecureWebhooks.Signing;

/// <summary>Verifies Standard Webhooks signatures on the receiving side. Does not allocate and does not throw on bad input.</summary>
/// <remarks>
/// The timestamp check only bounds the replay window. Receivers should also deduplicate by <c>webhook-id</c>
/// for at least the tolerance window (the sender delivers at-least-once and keeps the id across retries).
/// </remarks>
public static class WebhookVerifier
{
    /// <summary>Default allowed clock difference in both directions, per the specification's guidance.</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromMinutes(5);

    /// <summary>Signature headers longer than this are rejected without parsing (DoS guard).</summary>
    public const int MaxSignatureHeaderLength = 4096;

    /// <summary>Signature headers with more entries than this are rejected (DoS guard).</summary>
    public const int MaxSignatures = 16;

    /// <summary>Verifies a webhook using <see cref="DefaultTolerance"/>.</summary>
    public static VerificationResult Verify(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<char> messageId,
        ReadOnlySpan<char> timestamp,
        ReadOnlySpan<char> signatureHeader,
        ReadOnlySpan<WebhookSecret> secrets,
        TimeProvider timeProvider) =>
        Verify(payload, messageId, timestamp, signatureHeader, secrets, timeProvider, DefaultTolerance);

    /// <summary>Verifies a webhook.</summary>
    /// <param name="payload">The raw request body bytes, exactly as received (do not re-serialize JSON).</param>
    /// <param name="messageId">The <c>webhook-id</c> header.</param>
    /// <param name="timestamp">The <c>webhook-timestamp</c> header.</param>
    /// <param name="signatureHeader">The <c>webhook-signature</c> header.</param>
    /// <param name="secrets">Secrets to accept; pass the old and the new secret during rotation.</param>
    /// <param name="timeProvider">Clock used for the timestamp check.</param>
    /// <param name="tolerance">Maximum allowed difference between the timestamp and now, in either direction (inclusive).</param>
    public static VerificationResult Verify(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<char> messageId,
        ReadOnlySpan<char> timestamp,
        ReadOnlySpan<char> signatureHeader,
        ReadOnlySpan<WebhookSecret> secrets,
        TimeProvider timeProvider,
        TimeSpan tolerance)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentOutOfRangeException.ThrowIfLessThan(tolerance, TimeSpan.Zero);

        if (messageId.IsEmpty || timestamp.IsEmpty || signatureHeader.IsEmpty)
        {
            return VerificationResult.MissingHeader;
        }

        if (!long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out long sentAt))
        {
            return VerificationResult.MalformedTimestamp;
        }

        long now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        long toleranceSeconds = (long)tolerance.TotalSeconds;
        if (sentAt < now - toleranceSeconds)
        {
            return VerificationResult.TimestampTooOld;
        }

        if (sentAt > now + toleranceSeconds)
        {
            return VerificationResult.TimestampTooNew;
        }

        if (signatureHeader.Length > MaxSignatureHeaderLength)
        {
            return VerificationResult.MalformedSignature;
        }

        // Decode every v1 entry up front; unknown versions (e.g. v1a) are ignored, malformed v1 entries are skipped.
        Span<byte> candidates = stackalloc byte[MaxSignatures * SignedContent.MacLength];
        int count = 0, entries = 0;
        bool sawMalformed = false;
        var rest = signatureHeader;
        while (!rest.IsEmpty)
        {
            int space = rest.IndexOf(' ');
            var entry = space < 0 ? rest : rest[..space];
            rest = space < 0 ? default : rest[(space + 1)..];
            if (entry.IsEmpty)
            {
                continue;
            }

            if (++entries > MaxSignatures)
            {
                return VerificationResult.MalformedSignature;
            }

            if (!entry.StartsWith("v1,", StringComparison.Ordinal))
            {
                continue;
            }

            var slot = candidates.Slice(count * SignedContent.MacLength, SignedContent.MacLength);
            if (Convert.TryFromBase64Chars(entry[3..], slot, out int written) && written == SignedContent.MacLength)
            {
                count++;
            }
            else
            {
                sawMalformed = true;
            }
        }

        if (count > 0 && Matches(payload, messageId, sentAt, secrets, candidates[..(count * SignedContent.MacLength)]))
        {
            return VerificationResult.Valid;
        }

        return sawMalformed ? VerificationResult.MalformedSignature : VerificationResult.NoMatchingSignature;
    }

    private static bool Matches(ReadOnlySpan<byte> payload, ReadOnlySpan<char> messageId, long timestamp, ReadOnlySpan<WebhookSecret> secrets, ReadOnlySpan<byte> candidates)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(SignedContent.GetMaxLength(messageId, payload.Length));
        try
        {
            var content = buffer.AsSpan(0, SignedContent.Write(buffer, messageId, timestamp, payload));
            Span<byte> expected = stackalloc byte[SignedContent.MacLength];
            foreach (var secret in secrets)
            {
                HMACSHA256.HashData(secret.Key, content, expected);
                for (int i = 0; i < candidates.Length; i += SignedContent.MacLength)
                {
                    if (CryptographicOperations.FixedTimeEquals(expected, candidates.Slice(i, SignedContent.MacLength)))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
