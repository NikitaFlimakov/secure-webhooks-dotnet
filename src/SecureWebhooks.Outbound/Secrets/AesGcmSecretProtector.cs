using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Outbound;

/// <summary>
/// AES-256-GCM secret protector. Envelope (base64url):
/// <c>[version:1][keyIdLength:1][keyId][nonce:12][ciphertext][tag:16]</c>, with the endpoint id as associated data.
/// Encrypts with the current key, decrypts with any key in the ring. Decrypted secrets are never cached.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretProtector
{
    private const byte Version = 1;
    private const int KeyLength = 32, NonceLength = 12, TagLength = 16, MaxKeyIdLength = 32;

    private readonly Dictionary<string, byte[]> _keys;
    private readonly string _currentKeyId;

    /// <summary>Creates the protector.</summary>
    /// <exception cref="ArgumentException">The key ring is invalid.</exception>
    public AesGcmSecretProtector(IOptions<SecretProtectionOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!TryLoadKeys(options.Value, out var keys, out var error))
        {
            throw new ArgumentException(error, nameof(options));
        }

        _keys = keys;
        _currentKeyId = options.Value.CurrentKeyId;
    }

    /// <inheritdoc />
    public string Protect(WebhookSecret secret, string endpointId)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrEmpty(endpointId);

        int header = 2 + _currentKeyId.Length;
        var envelope = new byte[header + NonceLength + secret.Key.Length + TagLength];
        envelope[0] = Version;
        envelope[1] = (byte)_currentKeyId.Length;
        Encoding.ASCII.GetBytes(_currentKeyId, envelope.AsSpan(2));
        var nonce = envelope.AsSpan(header, NonceLength);
        RandomNumberGenerator.Fill(nonce);

        // A new AesGcm per call: instances are not thread-safe and construction is cheap (see AesGcmBenchmarks).
        using var aes = new AesGcm(_keys[_currentKeyId], TagLength);
        aes.Encrypt(nonce, secret.Key, envelope.AsSpan(header + NonceLength, secret.Key.Length), envelope.AsSpan(envelope.Length - TagLength), Encoding.UTF8.GetBytes(endpointId));
        return ToBase64Url(envelope);
    }

    /// <inheritdoc />
    /// <exception cref="CryptographicException">The value is malformed, uses an unknown key, was tampered with, or belongs to another endpoint.</exception>
    public WebhookSecret Unprotect(string protectedSecret, string endpointId)
    {
        ArgumentNullException.ThrowIfNull(protectedSecret);
        ArgumentException.ThrowIfNullOrEmpty(endpointId);

        byte[] envelope = FromBase64Url(protectedSecret);
        int keyIdLength = envelope.Length > 1 ? envelope[1] : 0;
        int header = 2 + keyIdLength;
        int secretLength = envelope.Length - header - NonceLength - TagLength;
        if (envelope.Length < 2 || envelope[0] != Version || keyIdLength is 0 or > MaxKeyIdLength
            || secretLength is < WebhookSecret.MinKeyLength or > WebhookSecret.MaxKeyLength)
        {
            throw new CryptographicException("Malformed protected secret.");
        }

        if (!_keys.TryGetValue(Encoding.ASCII.GetString(envelope, 2, keyIdLength), out var key))
        {
            throw new CryptographicException("Protected secret uses an unknown key id.");
        }

        Span<byte> plaintext = stackalloc byte[WebhookSecret.MaxKeyLength];
        plaintext = plaintext[..secretLength];
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(envelope.AsSpan(header, NonceLength), envelope.AsSpan(header + NonceLength, secretLength), envelope.AsSpan(envelope.Length - TagLength), plaintext, Encoding.UTF8.GetBytes(endpointId));
            return WebhookSecret.FromBytes(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static bool TryLoadKeys(SecretProtectionOptions options, [NotNullWhen(true)] out Dictionary<string, byte[]>? keys, [NotNullWhen(false)] out string? error)
    {
        keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        error = null;
        Span<byte> buffer = stackalloc byte[KeyLength + 3];
        foreach (var (id, value) in options.Keys)
        {
            if (id.Length is 0 or > MaxKeyIdLength || !id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                error = $"Key id '{id}' must be 1-{MaxKeyIdLength} characters of [A-Za-z0-9_-].";
            }
            else if (!Convert.TryFromBase64String(value ?? "", buffer, out int written) || written != KeyLength)
            {
                error = $"Key '{id}' must be a base64-encoded {KeyLength}-byte key.";
            }
            else
            {
                keys[id] = buffer[..KeyLength].ToArray();
            }

            CryptographicOperations.ZeroMemory(buffer);
            if (error is not null)
            {
                break;
            }
        }

        error ??= keys.ContainsKey(options.CurrentKeyId) ? null : "CurrentKeyId must refer to a key in Keys.";
        if (error is not null)
        {
            keys = null;
            return false;
        }

        return true;
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        try
        {
            return Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '='));
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Malformed protected secret.", ex);
        }
    }
}
