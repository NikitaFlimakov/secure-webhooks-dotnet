// Sample: one app that both sends webhooks and receives them (it delivers to itself over loopback).
// The README quickstart snippets are copied from the marked regions below, so they always compile.
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMemoryCache();

// <sender-setup>
builder.Services
    .AddWebhookSending(options =>
    {
        if (builder.Environment.IsDevelopment())
        {
            // Only so this sample can deliver to itself. Never allow loopback or http in production.
            options.AllowHttp = true;
            options.AllowedNetworks.Add(IPNetwork.Parse("127.0.0.0/8"));
            options.AllowedNetworks.Add(IPNetwork.Parse("::1/128"));
        }
    })
    .AddAesGcmSecretProtection(options =>
    {
        // 32-byte AES keys from your secret store; keep old keys until all rows are re-encrypted.
        options.Keys["2026-10"] = builder.Configuration["Webhooks:EncryptionKey"]!;
        options.CurrentKeyId = "2026-10";
    })
    .AddWebhookDispatcher()
    .AddInMemoryWebhookStores(); // replace with your own durable IWebhookEndpointStore / IWebhookDeliveryStore
// </sender-setup>

var app = builder.Build();

// <sender-register>
app.MapPost("/endpoints", (RegisterEndpoint request, WebhookUrlValidator validator, ISecretProtector protector, InMemoryWebhookEndpointStore store) =>
{
    Uri.TryCreate(request.Url, UriKind.Absolute, out var url);
    var validation = validator.Validate(url); // friendly early rejection; the real check happens at connect time
    if (!validation.IsValid)
    {
        return Results.BadRequest(validation.Error);
    }

    var endpointId = "ep_" + Guid.NewGuid().ToString("N");
    var secret = WebhookSecret.Generate();
    store.Upsert(new WebhookEndpoint(endpointId, url!, [protector.Protect(secret, endpointId)]));
    return Results.Ok(new RegisteredEndpoint(endpointId, secret.Format())); // show the secret to the owner once
});
// </sender-register>

// <sender-enqueue>
app.MapPost("/invoices/{invoiceId}/paid", async (string invoiceId, string endpointId, IWebhookPublisher publisher, TimeProvider time, CancellationToken ct) =>
{
    // Serialize once; the exact same bytes are signed and sent on every attempt.
    var payload = JsonSerializer.SerializeToUtf8Bytes(
        new WebhookEvent("invoice.paid", time.GetUtcNow(), new InvoicePaid(invoiceId)), SampleJson.Default.WebhookEvent);
    var messageId = await publisher.EnqueueAsync(endpointId, "invoice.paid", payload, ct);
    return Results.Accepted(value: messageId);
});
// </sender-enqueue>

// <receiver>
// Receivers only need the SecureWebhooks.Signing package.
var receiverSecrets = new[] { WebhookSecret.Parse(app.Configuration["Webhooks:ReceiverSecret"]!) };

app.MapPost("/webhooks", async (HttpRequest request, IMemoryCache seen, ILogger<Program> logger) =>
{
    // Verify the raw bytes: the signature covers the exact body, so never re-serialize JSON first.
    using var body = new MemoryStream();
    await request.Body.CopyToAsync(body);
    string id = request.Headers[WebhookHeaders.Id].ToString();

    var result = WebhookVerifier.Verify(
        body.GetBuffer().AsSpan(0, (int)body.Length),
        id,
        request.Headers[WebhookHeaders.Timestamp].ToString(),
        request.Headers[WebhookHeaders.Signature].ToString(),
        receiverSecrets,
        TimeProvider.System);
    if (result != VerificationResult.Valid)
    {
        logger.LogWarning("Rejected webhook: {Result}", result);
        return Results.Unauthorized();
    }

    // The timestamp check only bounds replays to ±5 minutes, and delivery is at-least-once,
    // so deduplicate by webhook-id. In production use a unique index or Redis SET NX instead of a local cache.
    if (seen.TryGetValue(id, out _))
    {
        return Results.NoContent();
    }

    seen.Set(id, true, TimeSpan.FromDays(4)); // longer than the sender's retry horizon (~3 days)
    logger.LogInformation("Processing webhook {Id}", id);
    return Results.NoContent();
});
// </receiver>

if (app.Environment.IsDevelopment())
{
    // Demo endpoint that points back at this app's own receiver: POST /invoices/42/paid?endpointId=ep_demo
    var protector = app.Services.GetRequiredService<ISecretProtector>();
    app.Services.GetRequiredService<InMemoryWebhookEndpointStore>().Upsert(new WebhookEndpoint(
        "ep_demo", new Uri(app.Configuration["Webhooks:DemoEndpointUrl"]!), [protector.Protect(receiverSecrets[0], "ep_demo")]));
}

app.Run();

internal sealed record RegisterEndpoint(string Url);

internal sealed record RegisteredEndpoint(string Id, string Secret);

internal sealed record InvoicePaid(string InvoiceId);

internal sealed record WebhookEvent(string Type, DateTimeOffset Timestamp, InvoicePaid Data);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(WebhookEvent))]
internal sealed partial class SampleJson : JsonSerializerContext;
