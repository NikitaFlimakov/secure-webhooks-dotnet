using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace SecureWebhooks.Signing;

/// <summary>
/// A Standard Webhooks symmetric signing secret: <c>whsec_</c> followed by the base64 encoding of 24–64 random bytes.
/// </summary>
/// <remarks><see cref="ToString"/> is redacted so the secret does not end up in logs by accident; use <see cref="Format"/>.</remarks>
public sealed class WebhookSecret
{
    /// <summary>The serialization prefix defined by the Standard Webhooks specification.</summary>
    public const string Prefix = "whsec_";

    /// <summary>Minimum key length in bytes (192 bits), per the specification.</summary>
    public const int MinKeyLength = 24;

    /// <summary>Maximum key length in bytes (512 bits), per the specification.</summary>
    public const int MaxKeyLength = 64;

    /// <summary>Key length used by <see cref="Generate"/> when none is specified.</summary>
    public const int DefaultKeyLength = 32;

    private const int MaxBase64Length = (MaxKeyLength + 2) / 3 * 4;

    private readonly byte[] _key;

    private WebhookSecret(byte[] key) => _key = key;

    /// <summary>The raw key bytes.</summary>
    public ReadOnlySpan<byte> Key => _key;

    /// <summary>Generates a new secret from a cryptographically secure random number generator.</summary>
    public static WebhookSecret Generate(int keyLength = DefaultKeyLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keyLength, MinKeyLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(keyLength, MaxKeyLength);
        return new WebhookSecret(RandomNumberGenerator.GetBytes(keyLength));
    }

    /// <summary>Creates a secret from raw key bytes (copied).</summary>
    /// <exception cref="ArgumentException">The key is shorter than 24 or longer than 64 bytes.</exception>
    public static WebhookSecret FromBytes(ReadOnlySpan<byte> key)
    {
        if (key.Length is < MinKeyLength or > MaxKeyLength)
        {
            throw new ArgumentException($"Key must be between {MinKeyLength} and {MaxKeyLength} bytes.", nameof(key));
        }

        return new WebhookSecret(key.ToArray());
    }

    /// <summary>Parses a <c>whsec_</c> secret.</summary>
    /// <exception cref="FormatException">The value is not a valid secret.</exception>
    public static WebhookSecret Parse(string value) =>
        TryParse(value, out var secret) ? secret : throw new FormatException("Invalid webhook secret.");

    /// <summary>
    /// Parses a secret. Like the official Standard Webhooks libraries, the <c>whsec_</c> prefix and base64 padding are optional.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? value, [NotNullWhen(true)] out WebhookSecret? secret)
    {
        secret = null;
        var base64 = value.AsSpan();
        if (base64.StartsWith(Prefix, StringComparison.Ordinal))
        {
            base64 = base64[Prefix.Length..];
        }

        if (base64.IsEmpty || base64.Length > MaxBase64Length)
        {
            return false;
        }

        Span<char> padded = stackalloc char[MaxBase64Length + 3];
        base64.CopyTo(padded);
        int length = base64.Length;
        while (length % 4 != 0)
        {
            padded[length++] = '=';
        }

        Span<byte> key = stackalloc byte[MaxKeyLength + 3];
        bool ok = Convert.TryFromBase64Chars(padded[..length], key, out int written)
            && written is >= MinKeyLength and <= MaxKeyLength;
        if (ok)
        {
            secret = new WebhookSecret(key[..written].ToArray());
        }

        CryptographicOperations.ZeroMemory(key);
        return ok;
    }

    /// <summary>Serializes the secret as <c>whsec_</c> + base64.</summary>
    public string Format() => Prefix + Convert.ToBase64String(_key);

    /// <summary>Returns a redacted representation; never the secret itself.</summary>
    public override string ToString() => Prefix + "***";
}
