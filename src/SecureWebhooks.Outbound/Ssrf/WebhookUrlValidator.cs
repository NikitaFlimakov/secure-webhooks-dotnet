using System.Net;

namespace SecureWebhooks.Outbound;

/// <summary>Result of <see cref="WebhookUrlValidator.Validate"/>.</summary>
/// <param name="IsValid">Whether the URL was accepted.</param>
/// <param name="Error">A user-facing reason when rejected; safe to show to the endpoint owner.</param>
public readonly record struct UrlValidationResult(bool IsValid, string? Error)
{
    internal static UrlValidationResult Valid => new(true, null);

    internal static UrlValidationResult Invalid(string error) => new(false, error);
}

/// <summary>
/// Registration-time URL checks that give endpoint owners early, friendly errors.
/// This is not the security boundary: host names are re-resolved and every address is checked at connect time
/// by <see cref="SsrfSafeConnectCallback"/>.
/// </summary>
public sealed class WebhookUrlValidator(IpAddressPolicy policy, WebhookSendingOptions options)
{
    /// <summary>Validates an endpoint URL.</summary>
    public UrlValidationResult Validate(Uri? url)
    {
        if (url is null || !url.IsAbsoluteUri)
        {
            return UrlValidationResult.Invalid("The URL must be absolute.");
        }

        if (url.Scheme != Uri.UriSchemeHttps && !(options.AllowHttp && url.Scheme == Uri.UriSchemeHttp))
        {
            return UrlValidationResult.Invalid(options.AllowHttp ? "Only http and https URLs are allowed." : "Only https URLs are allowed.");
        }

        if (url.UserInfo.Length > 0)
        {
            return UrlValidationResult.Invalid("The URL must not contain credentials.");
        }

        string host = url.IdnHost.TrimEnd('.');
        if (host.Length == 0)
        {
            return UrlValidationResult.Invalid("The URL must have a host.");
        }

        if (options.AllowedPorts.Count > 0 && !options.AllowedPorts.Contains(url.Port))
        {
            return UrlValidationResult.Invalid("The port is not allowed.");
        }

        bool blocked = IPAddress.TryParse(host, out var address)
            ? !policy.IsAllowed(address)
            : host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);

        return blocked ? UrlValidationResult.Invalid("The destination address is not allowed.") : UrlValidationResult.Valid;
    }
}
