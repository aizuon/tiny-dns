using System.Collections.Concurrent;

namespace TinyDNS;

public sealed class RateLimiter
{
    private readonly ConcurrentDictionary<string, Queue<long>> _perServerWindows = new();
    private readonly Queue<long> _globalWindow = new();
    private readonly object _globalLock = new();
    private readonly int _maxQueriesPerServer;
    private readonly int _maxQueriesGlobal;
    private readonly long _windowTicks;

    public RateLimiter(int maxQueriesPerServerPerSecond, int maxQueriesGlobalPerSecond)
    {
        _maxQueriesPerServer = maxQueriesPerServerPerSecond;
        _maxQueriesGlobal = maxQueriesGlobalPerSecond;
        _windowTicks = TimeSpan.FromSeconds(1).Ticks;
    }

    public bool AllowQuery(string server)
    {
        var now = DateTime.UtcNow.Ticks;

        var window = _perServerWindows.GetOrAdd(server, _ => new Queue<long>());
        lock (window)
        {
            CleanWindow(window, now);
            if (window.Count >= _maxQueriesPerServer)
                return false;
        }

        lock (_globalLock)
        {
            CleanWindow(_globalWindow, now);
            if (_globalWindow.Count >= _maxQueriesGlobal)
                return false;

            _globalWindow.Enqueue(now);
        }

        lock (window)
        {
            window.Enqueue(now);
        }

        return true;
    }

    private void CleanWindow(Queue<long> window, long now)
    {
        var cutoff = now - _windowTicks;
        while (window.Count > 0 && window.Peek() < cutoff)
            window.Dequeue();
    }

    public void Cleanup()
    {
        var now = DateTime.UtcNow.Ticks;
        var emptyServers = new List<string>();

        foreach (var kvp in _perServerWindows)
        {
            lock (kvp.Value)
            {
                CleanWindow(kvp.Value, now);
                if (kvp.Value.Count == 0)
                    emptyServers.Add(kvp.Key);
            }
        }

        foreach (var server in emptyServers)
            _perServerWindows.TryRemove(server, out _);

        lock (_globalLock)
        {
            CleanWindow(_globalWindow, now);
        }
    }
}
