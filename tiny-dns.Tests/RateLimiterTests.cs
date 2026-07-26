namespace TinyDNS.Tests;

public sealed class RateLimiterTests
{
    [Fact]
    public async Task ConcurrentRequestsCannotOvershootTheLimits()
    {
        var limiter = new RateLimiter(
            maxQueriesPerServerPerSecond: 5,
            maxQueriesGlobalPerSecond: 5);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var attempts = Enumerable.Range(0, 100)
            .Select(async _ =>
            {
                await start.Task;
                return limiter.AllowQuery("192.0.2.1");
            })
            .ToArray();

        start.SetResult();
        var results = await Task.WhenAll(attempts);

        Assert.Equal(5, results.Count(static allowed => allowed));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    public void InvalidLimitsAreRejected(int perServer, int global)
    {
        Assert.ThrowsAny<ArgumentException>(() => new RateLimiter(perServer, global));
    }
}
