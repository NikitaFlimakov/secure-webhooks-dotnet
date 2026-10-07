using Microsoft.Extensions.Options;

namespace SecureWebhooks.Outbound;

[OptionsValidator]
internal sealed partial class WebhookSendingOptionsValidator : IValidateOptions<WebhookSendingOptions>;

[OptionsValidator]
internal sealed partial class WebhookDispatcherOptionsValidator : IValidateOptions<WebhookDispatcherOptions>;
