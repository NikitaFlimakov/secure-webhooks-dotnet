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
}
