# SecureWebhooks

[![CI](https://github.com/NikitaFlimakov/secure-webhooks-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/NikitaFlimakov/secure-webhooks-dotnet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Signed outbound webhooks for .NET 8 and 10, compatible with [Standard Webhooks](https://www.standardwebhooks.com/).
Includes SSRF protection that is safe against DNS rebinding, encrypted secrets, and resilient delivery.

Sending a webhook means making an HTTP request to a URL a customer typed in, from inside your network. Done
naively, that is a server-side request forgery primitive: `http://169.254.169.254/` reads your cloud credentials,
`http://10.0.0.5:6379/` talks to your Redis, and a hostname that resolves to a public IP at registration and a private
IP at send time (DNS rebinding) walks straight past URL validation. Receivers have the opposite problem: a webhook is
just an HTTP request from the internet, so they must verify authenticity, freshness and uniqueness. SecureWebhooks
handles both sides: HMAC signing and allocation-free verification, an SSRF guard that checks the IP the socket
actually connects to, AES-GCM-encrypted secrets bound to their endpoint, and a delivery engine with retries, circuit
breaking and graceful shutdown.

> This is an independent implementation of the Standard Webhooks specification, not an official Standard Webhooks package.

## Packages

| Package | Use it on | Dependencies |
| --- | --- | --- |
| `SecureWebhooks.Signing` | **Receivers** (and senders) | none |
| `SecureWebhooks.Outbound` | **Senders** | `SecureWebhooks.Signing`, `Microsoft.Extensions.{Http,Hosting.Abstractions,Logging.Abstractions,Options}` |

Both target `net8.0` and `net10.0` and are built with `IsAotCompatible=true`; the trimming and AOT analyzers report no warnings.

**Installation:** the packages are not published to NuGet yet. Clone the repository and add a project reference, or
build packages locally with `dotnet pack -c Release -o ./artifacts` and add `./artifacts` as a local NuGet source.

## Quickstart

The snippets below are copied verbatim from [`samples/SecureWebhooks.Sample`](samples/SecureWebhooks.Sample/Program.cs),
which builds in CI. Run it with `dotnet run --project samples/SecureWebhooks.Sample`, then
`curl -X POST "http://localhost:5080/invoices/42/paid?endpointId=ep_demo"`: the app delivers the webhook to its own
receiver.

### Sender: register services

```csharp
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
```

### Sender: register an endpoint

```csharp
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
```

### Sender: publish an event

```csharp
app.MapPost("/invoices/{invoiceId}/paid", async (string invoiceId, string endpointId, IWebhookPublisher publisher, TimeProvider time, CancellationToken ct) =>
{
    // Serialize once; the exact same bytes are signed and sent on every attempt.
    var payload = JsonSerializer.SerializeToUtf8Bytes(
        new WebhookEvent("invoice.paid", time.GetUtcNow(), new InvoicePaid(invoiceId)), SampleJson.Default.WebhookEvent);
    var messageId = await publisher.EnqueueAsync(endpointId, "invoice.paid", payload, ct);
    return Results.Accepted(value: messageId);
});
```

`EnqueueAsync` returns the `webhook-id`. Delivery is **at-least-once with no ordering guarantee**. Every attempt is
re-signed with a fresh timestamp and keeps the same `webhook-id`. If you run your own scheduler (Hangfire, Quartz, a
queue consumer), skip `AddWebhookDispatcher` and call `WebhookSender.SendAsync(endpoint, message, ct)`: it makes exactly
one attempt and returns an `AttemptResult` (`Success`, `Retryable`, `Permanent` or `EndpointGone`, plus status code,
`Retry-After`, duration and a sanitized error).

### Receiver (ASP.NET Core minimal API)

```csharp
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

    seen.Set(id, true, TimeSpan.FromDays(4)); // outlives the sender's retry horizon (~3.2 days plus jitter)
    logger.LogInformation("Processing webhook {Id}", id);
    return Results.NoContent();
});
```

Verification returns a `VerificationResult` enum and does not throw on bad input:
`Valid`, `MissingHeader`, `MalformedTimestamp`, `TimestampTooOld`, `TimestampTooNew`, `MalformedSignature` or `NoMatchingSignature`.
During secret rotation, pass both the old and the new secret.

**Replay protection is the receiver's job.** The ±5-minute timestamp window bounds how long a captured request stays
valid. Within that window, and for idempotency across retries, deduplicate on `webhook-id`. Use a unique index on a
processed-events table (`INSERT … ON CONFLICT DO NOTHING`) or Redis `SET webhook:{id} 1 NX EX 345600`. The dedup
window should outlive the sender's retry horizon (about 3.2 days with the default schedule, plus jitter).

## Threat model

Every row links to tests in [`tests/SecureWebhooks.Tests`](tests/SecureWebhooks.Tests), all of which pass in CI.

| Threat | Mitigation | Proven by |
| --- | --- | --- |
| Forged or modified payload | HMAC-SHA256 over `{id}.{timestamp}.{raw body}` (spec `v1`); verifier recomputes over the exact received bytes | `WebhookVerifierTests.Official_spec_vector_is_valid`, `.Tampered_payload_is_rejected`, `.Tampered_message_id_is_rejected`, `.Tampered_timestamp_within_tolerance_is_rejected`, `WebhookSignerTests.Sign_matches_official_spec_vector` |
| Replay of a captured request | Timestamp is signed and must be within ±5 min (inclusive, both directions); receivers dedupe on `webhook-id` (see above) | `WebhookVerifierTests.Tolerance_is_inclusive_in_both_directions`, `.Custom_tolerance_is_respected` |
| Timing attack on signature comparison | `CryptographicOperations.FixedTimeEquals` on decoded 32-byte MACs | By construction; timing is not unit-testable. Functional coverage: `WebhookVerifierTests.Official_invalid_signature_vector_does_not_match` |
| SSRF to cloud metadata / internal hosts | Every resolved address is checked against IANA special-purpose ranges at **connect time**; URL validation at registration is only an early, friendly error | `IpAddressPolicyTests.Denies_ipv4_special_purpose_ranges`, `.Denies_ipv6_special_purpose_and_non_global_ranges`, `SsrfIntegrationTests.Host_resolving_to_cloud_metadata_is_blocked`, `.Loopback_is_blocked_by_default` |
| Obfuscated or IPv6-wrapped internal addresses (`2130706433`, `0x7f.0.0.1`, `[::ffff:127.0.0.1]`, NAT64, 6to4) | `Uri` canonicalization plus extraction of embedded IPv4 before re-checking | `WebhookUrlValidatorTests.Rejects_unsafe_urls`, `IpAddressPolicyTests.Obfuscated_ipv4_literals_parse_to_loopback_and_are_denied`, `.Denies_ipv6_forms_embedding_a_denied_ipv4` |
| DNS rebinding (public IP when checked, private IP when connecting) | `ConnectCallback` resolves once, validates **all** addresses, and connects the socket to the validated `IPAddress`; TLS/SNI still use the hostname | `SsrfIntegrationTests.Dns_rebinding_to_an_internal_address_is_blocked_on_the_next_connection`, `.Socket_connects_to_the_validated_address_and_keeps_the_original_host`, `.Any_disallowed_address_rejects_the_whole_host` |
| Redirect to an internal URL | `AllowAutoRedirect = false`; 3xx counts as a failed attempt | `SsrfIntegrationTests.Redirects_are_not_followed`, `WebhookSenderIntegrationTests.Redirect_to_metadata_service_is_not_followed` |
| Proxy bypass (validating the proxy instead of the target) | `UseProxy = false` on the hardened handler | `SsrfIntegrationTests.Handler_is_hardened`, `ServiceRegistrationTests.Named_client_uses_the_hardened_handler_without_url_logging_handlers` |
| Decompression bomb / huge or slow response | `AutomaticDecompression = None`, `ResponseHeadersRead`, at most 4 KB of the body read, 16 KB header cap, per-attempt timeout | `WebhookSenderIntegrationTests.Oversized_response_body_is_not_read_beyond_the_limit`, `WebhookSenderTests.Attempt_times_out_using_the_time_provider` |
| Secret leak from a database dump | Secrets stored as AES-256-GCM ciphertext (versioned envelope, random nonce, key ring with rotation) | `AesGcmSecretProtectorTests.Round_trips_a_secret`, `.Tampering_with_any_byte_fails`, `.Rotation_new_key_encrypts_and_old_key_still_decrypts` |
| Secret swapped between endpoint rows | Endpoint id is the AEAD associated data | `AesGcmSecretProtectorTests.Secret_copied_to_another_endpoint_row_does_not_decrypt`, `WebhookSenderTests.Undecryptable_secret_is_retryable_and_nothing_is_sent` |
| Header DoS against the verifier | Signature header capped at 4096 chars and 16 entries; no allocation, no exceptions | `WebhookVerifierTests.Oversized_signature_header_is_rejected_before_parsing`, `.Too_many_signatures_are_rejected` |
| Internal topology leaking to tenants via errors or logs | Generic `SsrfBlockedException` message, error categories instead of exception messages, logs carry scheme/host/port only, `IHttpClientFactory` URL loggers removed | `WebhookSenderIntegrationTests.Host_resolving_to_loopback_is_blocked_permanently_with_a_sanitized_error`, `WebhookSenderTests.Network_errors_are_retryable_and_sanitized`, `WebhookUrlValidatorTests.Error_messages_do_not_echo_the_address` |

Out of scope: a compromised sender host, a malicious receiver acting on the data it legitimately receives, and
network-level egress controls. Run webhook workers in a subnet that cannot reach internal services as defense in
depth, as the Standard Webhooks spec also recommends.

## Design decisions

- **The connect-time check is the authority.** URL validation at registration time cannot see what a hostname will
  resolve to later. `SsrfSafeConnectCallback` runs inside `SocketsHttpHandler` for every new connection, validates
  the resolved addresses and connects to one of them directly. Because nothing re-resolves the name between the check
  and the connect, there is no rebinding window. `PooledConnectionLifetime` (default 2 min) bounds how long a validated
  connection is reused. The trade-off is one DNS lookup per new connection, done by us rather than the handler.
- **Reject if *any* address is disallowed, rather than filtering.** A host that resolves to both a public and a
  private IP is either misconfigured or hostile. Filtering would make the outcome depend on record order and invites
  partial-rebinding tricks. The cost: a legitimate split-horizon host is rejected outright (use `AllowedNetworks`).
- **IPv6: allow-list global unicast (`2000::/3`), then deny specific ranges.** That's stricter than enumerating
  special ranges, and it stays safe if IANA adds more. IPv4 embedded via IPv4-mapped, NAT64 and 6to4 is extracted and
  re-checked. Teredo (`2001::/32`) is denied outright: its client address is obfuscated and the protocol is obsolete.
- **Re-sign every attempt; keep the `webhook-id`.** Retries span days, so a signature from the first attempt would
  fail the receiver's 5-minute window. A stable id lets receivers deduplicate.
- **Signing builds content in a pooled buffer, never a string.** The benchmarks below compare `IncrementalHash` with a
  rented buffer plus one-shot `HMACSHA256.HashData`. The one-shot version is as fast or faster and allocates nothing
  (`IncrementalHash` allocates an object per call), so it is the one used.
- **No decrypted-secret cache.** Decryption costs about a microsecond (measured below) against a network round trip
  of milliseconds, and a cache would keep plaintext keys in memory indefinitely. A new `AesGcm` is created per call
  because instances are not thread-safe and construction is cheap enough not to justify pooling. Decrypted key
  buffers are zeroed; the `WebhookSecret` object itself is managed memory and lives until collected.
- **At-least-once, no ordering.** Leases expire (lease = 2 × attempt timeout + 30 s), so a crashed worker's deliveries
  are retried, which can cause duplicates. Ordering would need per-endpoint serialization, which reintroduces
  head-of-line blocking.
- **No head-of-line blocking.** One pump leases only as many deliveries as there are idle workers and caps in-flight
  attempts per endpoint (default 4 of 32), so one slow endpoint cannot occupy every worker.
- **In-memory, per-process circuit breaker.** It opens after 5 consecutive failures, waits a 1-minute cooldown, then
  lets a single half-open probe through. While it is open, deliveries are rescheduled without consuming an attempt.
  Each instance trips independently; sharing state through the store would add a write per attempt. The optional
  auto-disable after `DisableAfter` (5 days) of continuous failure is also tracked per process.
- **Classification follows the spec.** 2xx is success; 410 disables the endpoint; an invalid URL or an SSRF block is
  permanent; everything else (3xx, 4xx, 5xx, timeouts, network errors) is retried. The next attempt is
  `max(schedule ± 20%, min(Retry-After, MaxRetryAfter))`. The default schedule is the spec's example:
  immediately, 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 14 h, 20 h, 24 h. A secret that cannot be decrypted is also
  retryable: it is usually a key-ring misconfiguration that an operator can fix.
- **Two packages.** Receivers install only `SecureWebhooks.Signing`, which has zero dependencies.
- **Single-attempt sender separate from the dispatcher.** `WebhookSender` has no retry state, so it plugs into any
  scheduler. `WebhookDispatcher` is just one driver for it.

## Benchmarks

Measured with BenchmarkDotNet v0.15.8 on Windows 11 (25H2) with an AMD Ryzen 9 8945HS (8 cores, 16 threads) and
.NET 10.0.0 (X64 RyuJIT, x86-64-v4), using the `MediumRun` job (2 launches × 15 iterations). Only .NET 10 was
measured. To reproduce:

```
dotnet run -c Release --project benchmarks/SecureWebhooks.Benchmarks -- --filter '*' --job medium
```

**Signing and verification** (one secret, `SigningBenchmarks`):

| Method | Payload | Mean | StdDev | Allocated |
| --- | ---: | ---: | ---: | ---: |
| (a) `IncrementalHash.CreateHMAC` | 256 B | 557.3 ns | 21.08 ns | 288 B |
| (b) rented buffer + `HMACSHA256.HashData` | 256 B | 351.5 ns | 5.21 ns | 0 B |
| `WebhookSigner.Sign` | 256 B | 410.9 ns | 8.28 ns | 120 B |
| `WebhookVerifier.Verify` | 256 B | 505.9 ns | 7.62 ns | 0 B |
| (a) `IncrementalHash.CreateHMAC` | 16 KB | 7,179.6 ns | 22.60 ns | 288 B |
| (b) rented buffer + `HMACSHA256.HashData` | 16 KB | 7,194.3 ns | 57.64 ns | 0 B |
| `WebhookSigner.Sign` | 16 KB | 7,209.0 ns | 23.52 ns | 120 B |
| `WebhookVerifier.Verify` | 16 KB | 7,313.0 ns | 24.23 ns | 0 B |

- Approach (b) is 1.6× faster at 256 B and allocates nothing. At 16 KB the two are equal because SHA-256 over the
  payload dominates. (b) is what the library uses.
- `Sign` allocates **only its result**: 120 B is the 47-character `v1,<base64>` string.
- `Verify` allocates **0 B**, as targeted.

**IP policy** (`IpAddressPolicyBenchmarks`), against a naive loop over `System.Net.IPNetwork.Contains` with the IPv4
deny list only (the baseline does less work: no IPv6 rules):

| Address | `IPNetwork.Contains` loop | `IpAddressPolicy.IsAllowed` | Allocated (policy) |
| --- | ---: | ---: | ---: |
| `8.8.8.8` | 23.24 ns | 6.27 ns | 0 B |
| `192.168.1.1` | 16.11 ns | 4.99 ns | 0 B |
| `2606:4700:4700::1111` | 23.82 ns | 5.24 ns | 0 B |
| `::ffff:169.254.169.254` | 13.31 ns (40 B) | 6.02 ns | 0 B |

**Secret decryption** (`SecretProtectorBenchmarks`):

| Method | Mean | StdDev | Allocated |
| --- | ---: | ---: | ---: |
| `AesGcm.Decrypt`, shared instance | 121.8 ns | 1.17 ns | 0 B |
| `AesGcm.Decrypt`, new instance per call | 526.1 ns | 3.64 ns | 40 B |
| `AesGcmSecretProtector.Unprotect` (base64url, envelope parse, new `AesGcm`) | 747.1 ns | 17.56 ns | 880 B |

Creating an `AesGcm` per call costs about 0.4 µs. Pooling would save that much per attempt, against a network round
trip measured in milliseconds, so the protector does not pool. `Unprotect` is not on a hot path, and its 880 B of
allocations (decoded envelope, AAD bytes, key-id string, the resulting `WebhookSecret`) are accepted.

## Non-goals

- **A durable store implementation.** `IWebhookEndpointStore` and `IWebhookDeliveryStore` are small, with lease and
  complete semantics that map to one SQL statement each (see the XML docs). Only in-memory implementations ship, for
  tests and the sample.
- **A receiver-side replay cache.** Deduplicate in your own database or cache, as shown above.
- **Asymmetric (`v1a`, ed25519) signatures.** `v1a` entries in a signature header are ignored, not rejected.
- **A management API or UI**, payload transformation, or fan-out to multiple endpoints. Call `EnqueueAsync` once per endpoint.
- **Ordering guarantees.**

## Comparison with alternatives

| | What it is | Relation to this library |
| --- | --- | --- |
| [`StandardWebhooks.StandardWebhooks`](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/csharp) (NuGet 1.0.1) | The reference C# library from the spec repository; targets `net5.0`/`netstandard2.0`. `Sign(msgId, timestamp, string payload)` and `Verify(string payload, WebHeaderCollection headers)`, which throws `WebhookVerificationException`; fixed 5-minute tolerance; constant-time string comparison. | Same signature scheme and test vectors. This library verifies raw bytes, returns a result enum instead of throwing, has a configurable tolerance and `TimeProvider`, and adds the sending side (SSRF guard, encryption, delivery). |
| [Svix](https://github.com/svix/svix-webhooks) | Webhook sending as a service: an open-source (MIT) server written in Rust, plus a hosted offering. Its .NET SDK (`Svix` on NuGet) is an API client that also includes a `Webhook` verifier. | Svix runs as a separate service you call over HTTP. SecureWebhooks is an in-process library: no extra infrastructure, but you provide the durable store and operations. |
| [smokescreen](https://github.com/stripe/smokescreen) | Stripe's open-source (MIT) HTTP CONNECT egress proxy in Go; resolves each host and refuses non-public IPs, with allow/deny lists. Mentioned by the Standard Webhooks spec's SSRF section. | It solves SSRF at the network layer for every language. SecureWebhooks does it in-process, without deploying a proxy. They are complementary: running both is defense in depth. If you send through a proxy, the in-process check would validate the proxy, which is why `UseProxy` is off. |

## License

[MIT](LICENSE) © 2026 Nikita Flimakov. Security issues: see [SECURITY.md](SECURITY.md).
