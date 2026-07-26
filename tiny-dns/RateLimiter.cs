using System.Collections.Concurrent;
using System.Diagnostics;

namespace TinyDNS;

public sealed class RateLimiter
{
    private sealed class ServerWindow
    {
        public Queue<long> Timestamps { get; } = new();
        public bool Retired { get; set; }
    }

    private readonly ConcurrentDictionary<string, ServerWindow> _perServerWindows =
        new(StringComparer.Ordinal);

    private readonly Queue<long> _globalWindow = new();
    private readonly object _globalLock = new();
    private readonly int _maxQueriesPerServer;
    private readonly int _maxQueriesGlobal;
    private readonly long _windowTicks;

    public RateLimiter(int maxQueriesPerServerPerSecond, int maxQueriesGlobalPerSecond)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxQueriesPerServerPerSecond);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxQueriesGlobalPerSecond);

        if (maxQueriesPerServerPerSecond > maxQueriesGlobalPerSecond)
        {
            throw new ArgumentException(
                "The per-server query limit cannot exceed the global query limit.",
                nameof(maxQueriesPerServerPerSecond));
        }

        _maxQueriesPerServer = maxQueriesPerServerPerSecond;
        _maxQueriesGlobal = maxQueriesGlobalPerSecond;
        _windowTicks = Stopwatch.Frequency;
    }

    public bool AllowQuery(string server)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(server);

        lock (_globalLock)
        {
            var now = Stopwatch.GetTimestamp();
            CleanWindow(_globalWindow, now);
            if (_globalWindow.Count >= _maxQueriesGlobal)
                return false;

            while (true)
            {
                var serverWindow = _perServerWindows.GetOrAdd(server, static _ => new ServerWindow());
                lock (serverWindow)
                {
                    if (serverWindow.Retired)
                        continue;

                    CleanWindow(serverWindow.Timestamps, now);
                    if (serverWindow.Timestamps.Count >= _maxQueriesPerServer)
                        return false;

                    serverWindow.Timestamps.Enqueue(now);
                    _globalWindow.Enqueue(now);
                    return true;
                }
            }
        }
    }

    public void Cleanup()
    {
        var now = Stopwatch.GetTimestamp();

        foreach (var entry in _perServerWindows)
        {
            lock (entry.Value)
            {
                CleanWindow(entry.Value.Timestamps, now);
                if (entry.Value.Timestamps.Count != 0)
                    continue;

                entry.Value.Retired = true;
                _perServerWindows.TryRemove(entry);
            }
        }

        lock (_globalLock)
        {
            CleanWindow(_globalWindow, now);
        }
    }

    private void CleanWindow(Queue<long> window, long now)
    {
        var cutoff = now - _windowTicks;
        while (window.TryPeek(out var timestamp) && timestamp <= cutoff)
            window.Dequeue();
    }
}
