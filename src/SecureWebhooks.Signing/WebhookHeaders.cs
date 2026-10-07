namespace SecureWebhooks.Signing;

/// <summary>Header names defined by the Standard Webhooks specification.</summary>
public static class WebhookHeaders
{
    /// <summary>Unique message identifier; identical across retries. Use it as an idempotency key.</summary>
    public const string Id = "webhook-id";

    /// <summary>Attempt timestamp in Unix seconds.</summary>
    public const string Timestamp = "webhook-timestamp";

    /// <summary>Space-delimited list of <c>version,base64signature</c> entries.</summary>
    public const string Signature = "webhook-signature";
}
