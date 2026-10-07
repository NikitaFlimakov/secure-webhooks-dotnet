using System.Collections.Concurrent;
using System.Net;
using SecureWebhooks.Outbound;

namespace SecureWebhooks.Tests.Infrastructure;

/// <summary>Returns queued answers in order; the last answer repeats. Simulates DNS rebinding.</summary>
internal sealed class FakeDnsResolver(params IPAddress[][] answers) : IDnsResolver
{
    private readonly ConcurrentQueue<IPAddress[]> _answers = new(answers);
    private IPAddress[] _last = [];

    public int Lookups;

    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Lookups);
        if (_answers.TryDequeue(out var next))
        {
            _last = next;
        }

        return Task.FromResult(_last);
    }
}
