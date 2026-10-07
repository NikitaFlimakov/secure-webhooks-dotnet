using SecureWebhooks.Outbound;

namespace SecureWebhooks.Tests.Delivery;

public sealed class RetryPolicyTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromHours(1);
    private static readonly IList<TimeSpan> Schedule = new WebhookDispatcherOptions().RetrySchedule;

    [Fact]
    public void Default_schedule_is_the_standard_webhooks_example() =>
        Assert.Equal(
            new[] { "00:00:00", "00:00:05", "00:05:00", "00:30:00", "02:00:00", "05:00:00", "10:00:00", "14:00:00", "20:00:00", "1.00:00:00" },
            Schedule.Select(t => t.ToString()));

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(9)]
    public void Jitter_stays_within_plus_minus_20_percent(int attemptsMade)
    {
        var nominal = Schedule[attemptsMade];

        var lowest = RetryPolicy.NextDelay(Schedule, attemptsMade, null, Cap, 0.0)!.Value;
        var highest = RetryPolicy.NextDelay(Schedule, attemptsMade, null, Cap, 0.999999)!.Value;

        Assert.Equal(nominal * 0.8, lowest);
        Assert.True(highest < nominal * 1.2 && highest > nominal * 1.19);
        for (int i = 0; i < 1000; i++)
        {
            var delay = RetryPolicy.NextDelay(Schedule, attemptsMade, null, Cap, Random.Shared.NextDouble())!.Value;
            Assert.InRange(delay, nominal * 0.8, nominal * 1.2);
        }
    }

    [Fact]
    public void Exhausted_schedule_returns_null() =>
        Assert.Null(RetryPolicy.NextDelay(Schedule, Schedule.Count, null, Cap, 0.5));

    [Fact]
    public void Retry_after_wins_when_longer_than_the_schedule() =>
        Assert.Equal(TimeSpan.FromMinutes(10), RetryPolicy.NextDelay(Schedule, 1, TimeSpan.FromMinutes(10), Cap, 0.5));

    [Fact]
    public void Schedule_wins_when_longer_than_retry_after() =>
        Assert.Equal(TimeSpan.FromMinutes(5), RetryPolicy.NextDelay(Schedule, 2, TimeSpan.FromSeconds(1), Cap, 0.5));

    [Fact]
    public void Retry_after_is_capped() =>
        Assert.Equal(Cap, RetryPolicy.NextDelay(Schedule, 1, TimeSpan.FromDays(30), Cap, 0.5));

    [Fact]
    public void Cap_does_not_shorten_the_schedule() =>
        Assert.Equal(TimeSpan.FromHours(24), RetryPolicy.NextDelay(Schedule, 9, TimeSpan.FromDays(30), Cap, 0.5));
}
