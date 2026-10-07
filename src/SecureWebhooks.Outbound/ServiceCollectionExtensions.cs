using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecureWebhooks.Outbound;

/// <summary>Dependency injection registration.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="WebhookSender"/>, the URL validator and the SSRF-hardened named <see cref="HttpClient"/>
    /// (<see cref="WebhookSender.HttpClientName"/>). Requires an <see cref="ISecretProtector"/>, e.g. via
    /// <see cref="AddAesGcmSecretProtection"/>. Add your own delegating handlers with
    /// <c>services.AddHttpClient(WebhookSender.HttpClientName).AddHttpMessageHandler(...)</c>.
    /// </summary>
    public static IServiceCollection AddWebhookSending(this IServiceCollection services, Action<WebhookSendingOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<WebhookSendingOptions>().Configure(configure ?? (_ => { })).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<WebhookSendingOptions>, WebhookSendingOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp =>
        {
            var options = SendingOptions(sp);
            return new IpAddressPolicy(options.AllowedNetworks, options.DeniedNetworks);
        });
        services.TryAddSingleton(sp => new WebhookUrlValidator(sp.GetRequiredService<IpAddressPolicy>(), SendingOptions(sp)));
        services.TryAddSingleton(sp => new SsrfSafeConnectCallback(sp.GetRequiredService<IpAddressPolicy>(), sp.GetService<ILogger<SsrfSafeConnectCallback>>()));
        services.TryAddSingleton(sp => new WebhookSender(
            sp.GetRequiredService<IHttpClientFactory>(),
            sp.GetRequiredService<ISecretProtector>(),
            sp.GetRequiredService<WebhookUrlValidator>(),
            sp.GetRequiredService<IOptions<WebhookSendingOptions>>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetService<ILogger<WebhookSender>>()));

        services.AddHttpClient(WebhookSender.HttpClientName, client => client.Timeout = Timeout.InfiniteTimeSpan) // per-attempt timeout is ours
            .ConfigurePrimaryHttpMessageHandler(sp => sp.GetRequiredService<SsrfSafeConnectCallback>().CreateHandler(SendingOptions(sp)))
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan) // PooledConnectionLifetime already re-resolves DNS
            .RemoveAllLoggers(); // the default handlers log full URIs, including query strings that may carry tokens
        return services;
    }

    /// <summary>Registers <see cref="AesGcmSecretProtector"/> as the <see cref="ISecretProtector"/>; the key ring is validated on start.</summary>
    public static IServiceCollection AddAesGcmSecretProtection(this IServiceCollection services, Action<SecretProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<SecretProtectionOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SecretProtectionOptions>, SecretProtectionOptionsValidator>());
        services.TryAddSingleton<ISecretProtector>(sp => new AesGcmSecretProtector(sp.GetRequiredService<IOptions<SecretProtectionOptions>>()));
        return services;
    }

    /// <summary>
    /// Registers <see cref="IWebhookPublisher"/> and the background dispatcher. Requires <see cref="AddWebhookSending"/>,
    /// an <see cref="IWebhookEndpointStore"/> and an <see cref="IWebhookDeliveryStore"/>.
    /// </summary>
    public static IServiceCollection AddWebhookDispatcher(this IServiceCollection services, Action<WebhookDispatcherOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<WebhookDispatcherOptions>().Configure(configure ?? (_ => { })).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<WebhookDispatcherOptions>, WebhookDispatcherOptionsValidator>());
        services.TryAddSingleton(_ => new DispatchSignal());
        services.TryAddSingleton<IWebhookPublisher>(sp => new WebhookPublisher(
            sp.GetRequiredService<IWebhookDeliveryStore>(),
            sp.GetRequiredService<DispatchSignal>(),
            sp.GetRequiredService<IOptions<WebhookDispatcherOptions>>(),
            sp.GetRequiredService<TimeProvider>()));
        services.AddHostedService(sp => new WebhookDispatcher(
            sp.GetRequiredService<IWebhookDeliveryStore>(),
            sp.GetRequiredService<IWebhookEndpointStore>(),
            sp.GetRequiredService<WebhookSender>(),
            sp.GetRequiredService<DispatchSignal>(),
            sp.GetRequiredService<IOptions<WebhookDispatcherOptions>>(),
            sp.GetRequiredService<IOptions<WebhookSendingOptions>>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILogger<WebhookDispatcher>>()));
        return services;
    }

    /// <summary>Registers the non-durable in-memory stores. For tests and samples only: deliveries are lost on restart.</summary>
    public static IServiceCollection AddInMemoryWebhookStores(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton(_ => new InMemoryWebhookEndpointStore());
        services.TryAddSingleton(_ => new InMemoryWebhookDeliveryStore());
        services.TryAddSingleton<IWebhookEndpointStore>(sp => sp.GetRequiredService<InMemoryWebhookEndpointStore>());
        services.TryAddSingleton<IWebhookDeliveryStore>(sp => sp.GetRequiredService<InMemoryWebhookDeliveryStore>());
        return services;
    }

    private static WebhookSendingOptions SendingOptions(IServiceProvider services) =>
        services.GetRequiredService<IOptions<WebhookSendingOptions>>().Value;
}
