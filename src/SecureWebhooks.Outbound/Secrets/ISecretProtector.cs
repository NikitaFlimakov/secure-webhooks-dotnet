using SecureWebhooks.Signing;

namespace SecureWebhooks.Outbound;

/// <summary>
/// Encrypts endpoint signing secrets at rest. Implement this to use a KMS or ASP.NET Core Data Protection instead of
/// <see cref="AesGcmSecretProtector"/>.
/// </summary>
/// <remarks>
/// Implementations must bind the ciphertext to <c>endpointId</c> so that a protected secret copied to another endpoint's
/// row does not decrypt. Failures must throw (typically <see cref="System.Security.Cryptography.CryptographicException"/>).
/// </remarks>
public interface ISecretProtector
{
    /// <summary>Encrypts <paramref name="secret"/> for storage alongside endpoint <paramref name="endpointId"/>.</summary>
    string Protect(WebhookSecret secret, string endpointId);

    /// <summary>Decrypts a value produced by <see cref="Protect"/> for the same <paramref name="endpointId"/>.</summary>
    WebhookSecret Unprotect(string protectedSecret, string endpointId);
}
