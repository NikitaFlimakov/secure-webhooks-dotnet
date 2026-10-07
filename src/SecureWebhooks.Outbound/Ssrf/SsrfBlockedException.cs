namespace SecureWebhooks.Outbound;

/// <summary>
/// Thrown when a webhook destination resolves to a disallowed address. Permanent: retrying will not help.
/// The message is deliberately generic so internal addresses are never revealed to endpoint owners.
/// </summary>
public sealed class SsrfBlockedException : Exception
{
    /// <summary>Creates the exception with the default, sanitized message.</summary>
    public SsrfBlockedException()
        : base("The webhook destination is not allowed.")
    {
    }

    /// <summary>Creates the exception with a custom message.</summary>
    public SsrfBlockedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a custom message and inner exception.</summary>
    public SsrfBlockedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
