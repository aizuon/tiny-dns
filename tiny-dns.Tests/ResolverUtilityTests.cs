using System.Net;
using TinyDNS.Packets;

namespace TinyDNS.Tests;

public sealed class ResolverUtilityTests
{
    [Fact]
    public async Task QueryNameserversWaitsForAUsefulResult()
    {
        var nameservers = new List<IPAddress>
        {
            IPAddress.Parse("192.0.2.1"),
            IPAddress.Parse("192.0.2.2")
        };

        var result = await RecursiveResolver.QueryNameserversInParallel<DNSResourceRecord[]>(
            nameservers,
            async (server, ct) =>
            {
                if (server.Equals(nameservers[0]))
                {
                    await Task.Delay(5, ct);
                    return [];
                }

                await Task.Delay(30, ct);
                return [new DNSResourceRecord { Name = "example.com" }];
            },
            static records => records is { Length: > 0 },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Single(result);
    }

    [Fact]
    public async Task QueryNameserversPropagatesCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var task = RecursiveResolver.QueryNameserversInParallel<string>(
            [IPAddress.Loopback, IPAddress.IPv6Loopback],
            async (_, ct) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                return "unreachable";
            },
            static result => result is not null,
            cancellation.Token).AsTask();

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    [Fact]
    public void NegativeTtlUsesTheLowerOfSoaTtlAndMinimum()
    {
        var authorities = new[]
        {
            new DNSResourceRecord
            {
                Type = (ushort)DNSRecordType.SOA,
                TTL = 120,
                ParsedRData = new SOARecord { Minimum = 300 }
            }
        };

        Assert.Equal(120u, RecursiveResolver.ExtractNegativeTTL(authorities));
        Assert.Equal(0u, RecursiveResolver.ExtractNegativeTTL([]));
    }

    [Theory]
    [InlineData("EXAMPLE.COM.", "example.com")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    public void QueryNamesAreNormalized(string input, string expected)
    {
        Assert.Equal(expected, RecursiveResolver.NormalizeQueryName(input));
    }

    [Fact]
    public void ReverseQuerySupportsIpv4AndIpv6()
    {
        Assert.Equal(
            "8.8.8.8.in-addr.arpa",
            RecursiveResolver.BuildReverseQuery(IPAddress.Parse("8.8.8.8")));
        Assert.Equal(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            RecursiveResolver.BuildReverseQuery(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public async Task DotRequiresAnExplicitForwarder()
    {
        var previousUseDot = RecursiveResolver.UseDnsOverTls;
        var previousForwarder = RecursiveResolver.ForwardingDnsServer;

        try
        {
            RecursiveResolver.UseDnsOverTls = true;
            RecursiveResolver.ForwardingDnsServer = null;

            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await RecursiveResolver.Resolve("example.com"));
        }
        finally
        {
            RecursiveResolver.UseDnsOverTls = previousUseDot;
            RecursiveResolver.ForwardingDnsServer = previousForwarder;
        }
    }

    [Fact]
    public async Task DohRequiresAnHttpsEndpoint()
    {
        var previousUseDoh = RecursiveResolver.UseDnsOverHttps;
        var previousDohUrl = RecursiveResolver.DnsOverHttpsUrl;

        try
        {
            RecursiveResolver.UseDnsOverHttps = true;
            RecursiveResolver.DnsOverHttpsUrl = "http://localhost/dns-query";

            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await RecursiveResolver.Resolve("invalid-doh-endpoint.example"));
        }
        finally
        {
            RecursiveResolver.UseDnsOverHttps = previousUseDoh;
            RecursiveResolver.DnsOverHttpsUrl = previousDohUrl;
        }
    }

    [Fact]
    public async Task ResolvePropagatesCallerCancellation()
    {
        var previousForwarder = RecursiveResolver.ForwardingDnsServer;
        var previousUseDoh = RecursiveResolver.UseDnsOverHttps;
        var previousUseDot = RecursiveResolver.UseDnsOverTls;
        using var cancellation = new CancellationTokenSource();

        try
        {
            RecursiveResolver.ForwardingDnsServer = null;
            RecursiveResolver.UseDnsOverHttps = false;
            RecursiveResolver.UseDnsOverTls = false;
            await cancellation.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await RecursiveResolver.Resolve("cancelled-query.example", cancellation.Token));
        }
        finally
        {
            RecursiveResolver.ForwardingDnsServer = previousForwarder;
            RecursiveResolver.UseDnsOverHttps = previousUseDoh;
            RecursiveResolver.UseDnsOverTls = previousUseDot;
        }
    }
}
