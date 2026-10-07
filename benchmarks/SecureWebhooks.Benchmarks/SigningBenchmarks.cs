using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Benchmarks;

/// <summary>
/// Compares the two candidate ways of computing HMAC-SHA256 over "{id}.{timestamp}.{payload}" without building a string,
/// then measures the public Sign/Verify APIs (which use the winner).
/// </summary>
[MemoryDiagnoser]
public class SigningBenchmarks
{
    private const string MessageId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    private static readonly DateTimeOffset Timestamp = DateTimeOffset.FromUnixTimeSeconds(1614265330);
    private static readonly byte[] Dot = [(byte)'.'];

    private readonly FixedTimeProvider _time = new(Timestamp);
    private WebhookSecret[] _secrets = null!;
    private byte[] _payload = null!;
    private string _header = null!;

    [Params(256, 16 * 1024)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _secrets = [WebhookSecret.Generate()];
        _payload = new byte[PayloadSize];
        new Random(42).NextBytes(_payload);
        _header = WebhookSigner.Sign(MessageId, Timestamp, _payload, _secrets);
    }

    [Benchmark(Description = "(a) IncrementalHash.CreateHMAC")]
    public byte IncrementalHmac()
    {
        Span<byte> mac = stackalloc byte[32];
        Span<byte> scratch = stackalloc byte[128];
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _secrets[0].Key);
        int idLength = Encoding.UTF8.GetBytes(MessageId, scratch);
        hmac.AppendData(scratch[..idLength]);
        hmac.AppendData(Dot);
        Utf8Formatter.TryFormat(Timestamp.ToUnixTimeSeconds(), scratch, out int tsLength);
        hmac.AppendData(scratch[..tsLength]);
        hmac.AppendData(Dot);
        hmac.AppendData(_payload);
        hmac.GetHashAndReset(mac);
        return mac[0];
    }

    [Benchmark(Baseline = true, Description = "(b) rented buffer + HMACSHA256.HashData")]
    public byte OneShotHmac()
    {
        Span<byte> mac = stackalloc byte[32];
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetByteCount(MessageId) + 22 + _payload.Length);
        int length = Encoding.UTF8.GetBytes(MessageId, buffer);
        buffer[length++] = (byte)'.';
        Utf8Formatter.TryFormat(Timestamp.ToUnixTimeSeconds(), buffer.AsSpan(length), out int tsLength);
        length += tsLength;
        buffer[length++] = (byte)'.';
        _payload.CopyTo(buffer.AsSpan(length));
        HMACSHA256.HashData(_secrets[0].Key, buffer.AsSpan(0, length + _payload.Length), mac);
        ArrayPool<byte>.Shared.Return(buffer);
        return mac[0];
    }

    [Benchmark(Description = "WebhookSigner.Sign")]
    public string Sign() => WebhookSigner.Sign(MessageId, Timestamp, _payload, _secrets);

    [Benchmark(Description = "WebhookVerifier.Verify")]
    public VerificationResult Verify() =>
        WebhookVerifier.Verify(_payload, MessageId, "1614265330", _header, _secrets, _time);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
