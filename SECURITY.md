# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/NikitaFlimakov/secure-webhooks-dotnet/security/advisories/new).

Please include affected versions, a description of the impact, and a minimal reproduction (a failing test is ideal).
You can expect an acknowledgement within 7 days. Fixes are developed in a private fork and released together with
a GitHub security advisory; reporters are credited unless they prefer otherwise.

SSRF bypasses are in scope and especially welcome. That includes address forms that reach a denied network,
rebinding races, or handler settings that let a request escape the connect-time check.

## Supported versions

The project is pre-1.0 and not yet published to NuGet. Only the latest commit on `main` receives security fixes.

| Version | Supported |
| --- | --- |
| `main` | ✅ |
| anything older | ❌ |

## Threat model

The README contains the [threat model](README.md#threat-model), which maps each threat to its mitigation and to
the tests that prove it. In short:

- **Receivers:** HMAC-SHA256 signatures verified in constant time, a ±5-minute timestamp window, and DoS limits on
  the signature header. Receivers must deduplicate on `webhook-id` themselves.
- **Senders:** the SSRF guard validates every resolved IP at connect time and connects to the validated address,
  which defeats DNS rebinding. Redirects, proxies, cookies and automatic decompression are disabled, and responses
  are read with bounds.
- **Secrets:** stored as AES-256-GCM ciphertext bound to the endpoint id, with a rotatable key ring. Decrypted
  secrets are never cached.

Defense in depth is still recommended: run webhook workers in a network segment that cannot reach internal services.
