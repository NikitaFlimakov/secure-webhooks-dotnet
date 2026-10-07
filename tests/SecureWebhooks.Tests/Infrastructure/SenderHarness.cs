using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using SecureWebhooks.Outbound;
using SecureWebhooks.Signing;

namespace SecureWebhooks.Tests.Infrastructure;

/// <summary>Builds a WebhookSender wired like production, with a pluggable handler.</summary>
internal sealed class SenderHarness
{
    public SenderHarness(TimeProvider time, Func<WebhookSendingOptions, HttpMessageHandler> handler, Action<WebhookSendingOptions>? configure = null)
    {
        Options = new WebhookSendingOptions();
        configure?.Invoke(Options);
        var protectionOptions = new SecretProtectionOptions { CurrentKeyId = "k1" };
        protectionOptions.Keys["k1"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Protector = new AesGcmSecretProtector(Microsoft.Extensions.Options.Options.Create(protectionOptions));
        var policy = new IpAddressPolicy(Options.AllowedNetworks, Options.DeniedNetworks);
        Handler = handler(Options);
        Sender = new WebhookSender(
            new TestHttpClientFactory(Handler),
            Protector,
            new WebhookUrlValidator(policy, Options),
            Microsoft.Extensions.Options.Options.Create(Options),
            time);
    }

    public WebhookSendingOptions Options { get; }

    public ISecretProtector Protector { get; }

    public HttpMessageHandler Handler { get; }

    public WebhookSender Sender { get; }

    public WebhookSecret Secret { get; } = WebhookSecret.Generate();

    public static SenderHarness WithStub(TimeProvider time, StubHandler stub, Action<WebhookSendingOptions>? configure = null) =>
        new(time, _ => stub, configure);

    public static SenderHarness WithHardenedHandler(TimeProvider time, IDnsResolver? dns = null, Action<WebhookSendingOptions>? configure = null) =>
        new(time, o => new SsrfSafeConnectCallback(new IpAddressPolicy(o.AllowedNetworks, o.DeniedNetworks), dns ?? SystemDnsResolver.Instance, null).CreateHandler(o), configure);

    public WebhookEndpoint Endpoint(Uri? url = null, string id = "ep_1", params WebhookSecret[] extraSecrets) =>
        new(id, url ?? new Uri("https://hooks.example.com/receive?token=abc"),
            [Protector.Protect(Secret, id), .. extraSecrets.Select(s => Protector.Protect(s, id))]);

    public static WebhookMessage Message(string id = "msg_1", string payload = "{\"type\":\"invoice.paid\"}") =>
        new(id, "invoice.paid", System.Text.Encoding.UTF8.GetBytes(payload));

    public static IPNetwork[] Loopback => [IPNetwork.Parse("127.0.0.0/8"), IPNetwork.Parse("::1/128")];
}
