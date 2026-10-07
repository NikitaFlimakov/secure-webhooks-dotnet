using System.Buffers;
using System.Security.Cryptography;

namespace SecureWebhooks.Signing;

/// <summary>Produces Standard Webhooks <c>webhook-signature</c> header values.</summary>
public static class WebhookSigner
{
    /// <summary>Maximum number of secrets accepted by <see cref="Sign"/> (current plus rotated-out ones).</summary>
    public const int MaxSecrets = 16;

    // "v1," + base64 of a 32-byte HMAC-SHA256.
    private const int SignatureLength = 3 + 44;

    /// <summary>
    /// Signs <c>{messageId}.{timestamp}.{payload}</c> with each secret and returns the space-delimited header value,
    /// e.g. <c>v1,K5oZ... v1,Ceo5...</c>. Signing with several secrets enables zero-downtime rotation.
    /// </summary>
    /// <param name="messageId">The <c>webhook-id</c>; must be non-empty and must not contain <c>'.'</c>.</param>
    /// <param name="timestamp">The attempt time; truncated to whole Unix seconds.</param>
    /// <param name="payload">The exact body bytes that will be sent.</param>
    /// <param name="secrets">One to <see cref="MaxSecrets"/> secrets.</param>
    public static string Sign(string messageId, DateTimeOffset timestamp, ReadOnlySpan<byte> payload, ReadOnlySpan<WebhookSecret> secrets)
    {
        ArgumentException.ThrowIfNullOrEmpty(messageId);
        if (messageId.Contains('.', StringComparison.Ordinal))
        {
            throw new ArgumentException("Message id must not contain '.'.", nameof(messageId));
        }

        if (secrets.Length is 0 or > MaxSecrets)
        {
            throw new ArgumentOutOfRangeException(nameof(secrets), $"Between 1 and {MaxSecrets} secrets are required.");
        }

        // One rented buffer holds the signed content followed by one MAC per secret,
        // so the header can be written by string.Create without a closure or extra allocations.
        int contentMax = SignedContent.GetMaxLength(messageId, payload.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(contentMax + (secrets.Length * SignedContent.MacLength));
        try
        {
            int contentLength = SignedContent.Write(buffer, messageId, timestamp.ToUnixTimeSeconds(), payload);
            var content = buffer.AsSpan(0, contentLength);
            for (int i = 0; i < secrets.Length; i++)
            {
                HMACSHA256.HashData(secrets[i].Key, content, buffer.AsSpan(contentMax + (i * SignedContent.MacLength), SignedContent.MacLength));
            }

            int headerLength = (secrets.Length * (SignatureLength + 1)) - 1;
            return string.Create(headerLength, (buffer, contentMax, secrets.Length), static (chars, state) =>
            {
                var (macs, offset, count) = state;
                for (int i = 0; i < count; i++)
                {
                    var slot = chars.Slice(i * (SignatureLength + 1));
                    if (i > 0)
                    {
                        chars[(i * (SignatureLength + 1)) - 1] = ' ';
                    }

                    "v1,".CopyTo(slot);
                    Convert.TryToBase64Chars(macs.AsSpan(offset + (i * SignedContent.MacLength), SignedContent.MacLength), slot[3..], out _);
                }
            });
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
