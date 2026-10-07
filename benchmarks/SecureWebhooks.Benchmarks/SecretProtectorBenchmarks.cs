using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Options;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Benchmarks;

/// <summary>
/// Measures the cost of constructing an AesGcm per call (what AesGcmSecretProtector does, because AesGcm is not
/// thread-safe) against reusing one instance, to decide whether pooling is worth it.
/// </summary>
[MemoryDiagnoser]
public class SecretProtectorBenchmarks
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(12);
    private readonly byte[] _plaintext = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _ciphertext = new byte[32];
    private readonly byte[] _tag = new byte[16];
    private readonly byte[] _aad = "ep_01HXYZ"u8.ToArray();
    private AesGcm _shared = null!;
    private AesGcmSecretProtector _protector = null!;
    private string _protected = null!;

    [GlobalSetup]
    public void Setup()
    {
        _shared = new AesGcm(_key, 16);
        _shared.Encrypt(_nonce, _plaintext, _ciphertext, _tag, _aad);
        var options = new SecretProtectionOptions { CurrentKeyId = "k1" };
        options.Keys["k1"] = Convert.ToBase64String(_key);
        _protector = new AesGcmSecretProtector(Options.Create(options));
        _protected = _protector.Protect(WebhookSecret.Generate(), "ep_01HXYZ");
    }

    [GlobalCleanup]
    public void Cleanup() => _shared.Dispose();

    [Benchmark(Baseline = true, Description = "Decrypt, shared AesGcm")]
    public byte DecryptShared()
    {
        Span<byte> output = stackalloc byte[32];
        _shared.Decrypt(_nonce, _ciphertext, _tag, output, _aad);
        return output[0];
    }

    [Benchmark(Description = "Decrypt, new AesGcm per call")]
    public byte DecryptNew()
    {
        Span<byte> output = stackalloc byte[32];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(_nonce, _ciphertext, _tag, output, _aad);
        return output[0];
    }

    [Benchmark(Description = "AesGcmSecretProtector.Unprotect")]
    public WebhookSecret Unprotect() => _protector.Unprotect(_protected, "ep_01HXYZ");
}
