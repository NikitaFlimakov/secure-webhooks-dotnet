using SecureWebhooks.Outbound;

namespace SecureWebhooks.Tests.Delivery;

public sealed class CircuitBreakerTests
{
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(1);
    private readonly CircuitBreaker _breaker = new(threshold: 3, Cooldown);
    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    private bool FailTimes(int count)
    {
        bool opened = false;
        for (int i = 0; i < count; i++)
        {
            opened = _breaker.RecordFailure("ep", _now).Opened;
        }

        return opened;
    }

    [Fact]
    public void Stays_closed_below_the_threshold()
    {
        Assert.False(FailTimes(2));
        Assert.Null(_breaker.TryAcquire("ep", _now));
    }

    [Fact]
    public void Opens_at_the_threshold_and_blocks_until_cooldown()
    {
        Assert.True(FailTimes(3));

        Assert.Equal(_now + Cooldown, _breaker.TryAcquire("ep", _now));
        Assert.Equal(_now + Cooldown, _breaker.TryAcquire("ep", _now + Cooldown - TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void Half_open_lets_exactly_one_probe_through()
    {
        FailTimes(3);
        _now += Cooldown;

        Assert.Null(_breaker.TryAcquire("ep", _now));
        Assert.NotNull(_breaker.TryAcquire("ep", _now));
    }

    [Fact]
    public void Successful_probe_closes_the_circuit()
    {
        FailTimes(3);
        _now += Cooldown;
        _breaker.TryAcquire("ep", _now);

        _breaker.RecordSuccess("ep");

        Assert.Null(_breaker.TryAcquire("ep", _now));
        Assert.Null(_breaker.TryAcquire("ep", _now));
        Assert.False(FailTimes(2));
    }

    [Fact]
    public void Failed_probe_reopens_the_circuit()
    {
        FailTimes(3);
        _now += Cooldown;
        _breaker.TryAcquire("ep", _now);

        var (opened, _) = _breaker.RecordFailure("ep", _now);

        Assert.True(opened);
        Assert.Equal(_now + Cooldown, _breaker.TryAcquire("ep", _now));
    }

    [Fact]
    public void Tracks_how_long_an_endpoint_has_been_failing()
    {
        _breaker.RecordFailure("ep", _now);
        Assert.Equal(TimeSpan.FromDays(2), _breaker.RecordFailure("ep", _now + TimeSpan.FromDays(2)).FailingFor);

        _breaker.RecordSuccess("ep");
        Assert.Equal(TimeSpan.Zero, _breaker.RecordFailure("ep", _now + TimeSpan.FromDays(3)).FailingFor);
    }

    [Fact]
    public void Endpoints_are_independent()
    {
        FailTimes(3);

        Assert.Null(_breaker.TryAcquire("other", _now));
    }
}
