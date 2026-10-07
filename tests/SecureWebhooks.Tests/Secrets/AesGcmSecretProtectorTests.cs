using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Tests.Secrets;

public sealed class AesGcmSecretProtectorTests
{
    private static readonly string Key1 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static readonly string Key2 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    internal static AesGcmSecretProtector Create(string currentKeyId = "k1", params (string Id, string Key)[] keys)
    {
        var options = new SecretProtectionOptions { CurrentKeyId = currentKeyId };
        foreach (var (id, key) in keys.Length == 0 ? [("k1", Key1)] : keys)
        {
            options.Keys[id] = key;
        }

        return new AesGcmSecretProtector(Options.Create(options));
    }

    [Fact]
    public void Round_trips_a_secret()
    {
        var protector = Create();
        var secret = WebhookSecret.Generate();

        var protectedSecret = protector.Protect(secret, "ep_1");

        Assert.True(protector.Unprotect(protectedSecret, "ep_1").Key.SequenceEqual(secret.Key));
        Assert.DoesNotContain(secret.Format()[6..], protectedSecret, StringComparison.Ordinal);
    }

    [Fact]
    public void Same_secret_encrypts_differently_each_time() // random nonce
    {
        var protector = Create();
        var secret = WebhookSecret.Generate();

        Assert.NotEqual(protector.Protect(secret, "ep_1"), protector.Protect(secret, "ep_1"));
    }

    [Fact]
    public void Output_is_base64url()
    {
        var value = Create().Protect(WebhookSecret.Generate(64), "ep_1");

        Assert.DoesNotContain('+', value);
        Assert.DoesNotContain('/', value);
        Assert.DoesNotContain('=', value);
    }

    [Fact]
    public void Tampering_with_any_byte_fails()
    {
        var protector = Create();
        var envelope = FromBase64Url(protector.Protect(WebhookSecret.Generate(), "ep_1"));

        for (int i = 0; i < envelope.Length; i++)
        {
            var tampered = (byte[])envelope.Clone();
            tampered[i] ^= 0x01;
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(ToBase64Url(tampered), "ep_1"));
        }
    }

    [Fact]
    public void Truncated_or_garbage_input_fails_cleanly()
    {
        var protector = Create();
        var value = protector.Protect(WebhookSecret.Generate(), "ep_1");

        foreach (var input in new[] { "", "A", "!!!!", value[..10], value[..^4], value + "AAAA" })
        {
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(input, "ep_1"));
        }
    }

    [Fact]
    public void Secret_copied_to_another_endpoint_row_does_not_decrypt()
    {
        var protector = Create();
        var value = protector.Protect(WebhookSecret.Generate(), "ep_1");

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(value, "ep_2"));
    }

    [Fact]
    public void Rotation_new_key_encrypts_and_old_key_still_decrypts()
    {
        var secret = WebhookSecret.Generate();
        var before = Create("k1", ("k1", Key1)).Protect(secret, "ep_1");

        var rotated = Create("k2", ("k1", Key1), ("k2", Key2));
        var after = rotated.Protect(secret, "ep_1");

        Assert.True(rotated.Unprotect(before, "ep_1").Key.SequenceEqual(secret.Key));
        Assert.Equal("k1", KeyIdOf(before));
        Assert.Equal("k2", KeyIdOf(after));
    }

    [Fact]
    public void Unknown_key_id_fails()
    {
        var value = Create("k1", ("k1", Key1)).Protect(WebhookSecret.Generate(), "ep_1");

        var retired = Create("k2", ("k2", Key2));

        var ex = Assert.ThrowsAny<CryptographicException>(() => retired.Unprotect(value, "ep_1"));
        Assert.Contains("unknown key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Same_key_id_with_a_different_key_fails() =>
        Assert.ThrowsAny<CryptographicException>(() =>
            Create("k1", ("k1", Key2)).Unprotect(Create("k1", ("k1", Key1)).Protect(WebhookSecret.Generate(), "ep_1"), "ep_1"));

    [Theory]
    [InlineData("k1", "not base64")]
    [InlineData("k1", "AAAA")] // 3 bytes
    [InlineData("bad id!", "")]
    [InlineData("", "")]
    public void Invalid_key_ring_is_rejected(string id, string key)
    {
        var options = new SecretProtectionOptions { CurrentKeyId = id };
        options.Keys[id] = key.Length == 0 ? Key1 : key;

        Assert.Throws<ArgumentException>(() => new AesGcmSecretProtector(Options.Create(options)));
        Assert.True(new SecretProtectionOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Current_key_must_exist()
    {
        var options = new SecretProtectionOptions { CurrentKeyId = "missing" };
        options.Keys["k1"] = Key1;

        Assert.True(new SecretProtectionOptionsValidator().Validate(null, options).Failed);
    }

    private static string KeyIdOf(string value)
    {
        var envelope = FromBase64Url(value);
        return System.Text.Encoding.ASCII.GetString(envelope, 2, envelope[1]);
    }

    private static byte[] FromBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '='));
    }

    private static string ToBase64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
