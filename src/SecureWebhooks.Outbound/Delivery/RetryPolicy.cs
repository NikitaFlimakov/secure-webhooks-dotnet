namespace SecureWebhooks.Outbound;

internal static class RetryPolicy
{
    private const double Jitter = 0.2;

    // Delay before the next attempt, or null when the schedule is exhausted. `random` in [0, 1) picks the jitter.
    public static TimeSpan? NextDelay(IList<TimeSpan> schedule, int attemptsMade, TimeSpan? retryAfter, TimeSpan maxRetryAfter, double random)
    {
        if (attemptsMade >= schedule.Count)
        {
            return null;
        }

        var delay = schedule[attemptsMade] * (1 - Jitter + (2 * Jitter * random));
        if (retryAfter is { } requested)
        {
            var capped = requested < maxRetryAfter ? requested : maxRetryAfter;
            delay = capped > delay ? capped : delay;
        }

        return delay;
    }
}

/// <summary>Per-endpoint circuit breaker. In-memory and per process: each instance trips independently.</summary>
internal sealed class CircuitBreaker(int threshold, TimeSpan cooldown)
{
    private readonly Dictionary<string, State> _states = new(StringComparer.Ordinal);

    /// <summary>Returns <see langword="null"/> if an attempt may proceed, otherwise when to try again.</summary>
    public DateTimeOffset? TryAcquire(string endpointId, DateTimeOffset now)
    {
        lock (_states)
        {
            if (!_states.TryGetValue(endpointId, out var state) || state.Failures < threshold)
            {
                return null; // closed
            }

            if (now < state.OpenUntil)
            {
                return state.OpenUntil; // open
            }

            if (state.ProbeInFlight)
            {
                return now + cooldown; // half-open, probe already running
            }

            state.ProbeInFlight = true; // half-open: this attempt is the probe
            return null;
        }
    }

    public void RecordSuccess(string endpointId)
    {
        lock (_states)
        {
            _states.Remove(endpointId);
        }
    }

    /// <summary>Records a failure; returns whether the circuit just opened and how long the endpoint has been failing.</summary>
    public (bool Opened, TimeSpan FailingFor) RecordFailure(string endpointId, DateTimeOffset now)
    {
        lock (_states)
        {
            if (!_states.TryGetValue(endpointId, out var state))
            {
                _states[endpointId] = state = new State { FailingSince = now };
            }

            bool wasProbe = state.ProbeInFlight;
            state.ProbeInFlight = false;
            state.Failures++;
            if (state.Failures >= threshold)
            {
                state.OpenUntil = now + cooldown;
            }

            return (state.Failures == threshold || wasProbe, now - state.FailingSince);
        }
    }

    private sealed class State
    {
        public int Failures;
        public bool ProbeInFlight;
        public DateTimeOffset OpenUntil;
        public DateTimeOffset FailingSince;
    }
}
