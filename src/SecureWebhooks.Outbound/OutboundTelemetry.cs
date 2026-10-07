using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SecureWebhooks.Outbound;

/// <summary>The <c>SecureWebhooks</c> ActivitySource and Meter.</summary>
internal static class OutboundTelemetry
{
    public const string Name = "SecureWebhooks";

    public static readonly ActivitySource ActivitySource = new(Name);
    public static readonly Meter Meter = new(Name);

    public static readonly Counter<long> SsrfBlocked = Meter.CreateCounter<long>("securewebhooks.ssrf_blocked", description: "Connections refused by the SSRF guard.");
    public static readonly Counter<long> Attempts = Meter.CreateCounter<long>("securewebhooks.attempts", description: "Delivery attempts.");
    public static readonly Counter<long> Succeeded = Meter.CreateCounter<long>("securewebhooks.succeeded", description: "Successful delivery attempts.");
    public static readonly Counter<long> Failed = Meter.CreateCounter<long>("securewebhooks.failed", description: "Failed delivery attempts.");
    public static readonly Histogram<double> AttemptDuration = Meter.CreateHistogram<double>("securewebhooks.attempt.duration", "s", "Duration of delivery attempts.");

    public static void RecordAttempt(AttemptResult result)
    {
        var outcome = new KeyValuePair<string, object?>("webhook.outcome", result.Outcome.ToString());
        Attempts.Add(1, outcome);
        (result.Outcome == AttemptOutcome.Success ? Succeeded : Failed).Add(1, outcome);
        AttemptDuration.Record(result.Duration.TotalSeconds, outcome);
    }
}
