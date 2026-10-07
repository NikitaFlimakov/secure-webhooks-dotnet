using System.Buffers.Text;
using System.Text;

namespace SecureWebhooks.Signing;

/// <summary>Builds the signed content <c>{id}.{timestamp}.{payload}</c> as UTF-8 bytes, never as a string.</summary>
internal static class SignedContent
{
    internal const int MacLength = 32;

    // A long formats to at most 20 characters ("-9223372036854775808"), plus two '.' separators.
    internal static int GetMaxLength(ReadOnlySpan<char> messageId, int payloadLength) =>
        Encoding.UTF8.GetByteCount(messageId) + 22 + payloadLength;

    internal static int Write(Span<byte> destination, ReadOnlySpan<char> messageId, long timestamp, ReadOnlySpan<byte> payload)
    {
        int length = Encoding.UTF8.GetBytes(messageId, destination);
        destination[length++] = (byte)'.';
        Utf8Formatter.TryFormat(timestamp, destination[length..], out int written);
        length += written;
        destination[length++] = (byte)'.';
        payload.CopyTo(destination[length..]);
        return length + payload.Length;
    }
}
