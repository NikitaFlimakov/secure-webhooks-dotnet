using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace SecureWebhooks.Outbound;

/// <summary>Options for background delivery.</summary>
[UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "The attributes are only read at compile time by the [OptionsValidator] source generator, which emits trimming-safe copies.")]
public sealed class WebhookDispatcherOptions
{
    /// <summary>Global cap on concurrent attempts (the worker pool size).</summary>
    [Range(1, 1024)]
    public int MaxConcurrency { get; set; } = 32;

    /// <summary>Cap on concurrent attempts to a single endpoint, so one slow endpoint cannot occupy every worker.</summary>
    [Range(1, 1024)]
    public int MaxConcurrencyPerEndpoint { get; set; } = 4;

    /// <summary>How often the store is polled for due deliveries when nothing was enqueued in-process.</summary>
    [Range(typeof(TimeSpan), "00:00:00.100", "01:00:00")]
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Delay before each attempt; its length is the maximum number of attempts. Each delay gets ±20% jitter.
    /// Default: the example schedule from the Standard Webhooks specification.
    /// </summary>
    [MinLength(1)]
    public IList<TimeSpan> RetrySchedule { get; } =
    [
        TimeSpan.Zero, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2),
        TimeSpan.FromHours(5), TimeSpan.FromHours(10), TimeSpan.FromHours(14), TimeSpan.FromHours(20), TimeSpan.FromHours(24),
    ];

    /// <summary>Upper bound for a receiver's <c>Retry-After</c>; the next attempt is <c>max(schedule, min(Retry-After, this))</c>.</summary>
    [Range(typeof(TimeSpan), "00:00:00", "7.00:00:00")]
    public TimeSpan MaxRetryAfter { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Consecutive failed attempts after which an endpoint's circuit opens.</summary>
    [Range(1, 10000)]
    public int CircuitBreakerThreshold { get; set; } = 5;

    /// <summary>How long an open circuit waits before letting a single probe attempt through.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "1.00:00:00")]
    public TimeSpan CircuitBreakerCooldown { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Disable an endpoint that has failed continuously for this long (per process). <see langword="null"/> turns this off.</summary>
    public TimeSpan? DisableAfter { get; set; } = TimeSpan.FromDays(5);

    /// <summary>On shutdown, in-flight attempts get this long to finish before they are cancelled (their leases then expire).</summary>
    [Range(typeof(TimeSpan), "00:00:00", "00:05:00")]
    public TimeSpan ShutdownTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Maximum payload size accepted by <see cref="IWebhookPublisher.EnqueueAsync"/>.</summary>
    [Range(1, 16 * 1024 * 1024)]
    public int MaxPayloadBytes { get; set; } = 256 * 1024;
}
