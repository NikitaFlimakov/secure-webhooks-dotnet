using Microsoft.Extensions.Options;

namespace SecureWebhooks.Outbound;

/// <summary>Key ring for <see cref="AesGcmSecretProtector"/>.</summary>
public sealed class SecretProtectionOptions
{
    /// <summary>Key id (1–32 ASCII letters, digits, '-' or '_') → base64-encoded 32-byte AES-256 key. Keep old keys until all rows are re-encrypted.</summary>
    public IDictionary<string, string> Keys { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Id of the key used for new encryptions; any key in <see cref="Keys"/> can decrypt.</summary>
    public string CurrentKeyId { get; set; } = "";
}

/// <summary>Validates <see cref="SecretProtectionOptions"/> (run on start).</summary>
internal sealed class SecretProtectionOptionsValidator : IValidateOptions<SecretProtectionOptions>
{
    public ValidateOptionsResult Validate(string? name, SecretProtectionOptions options) =>
        AesGcmSecretProtector.TryLoadKeys(options, out _, out var error) ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(error);
}
