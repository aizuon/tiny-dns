using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Caching.Memory;
using Serilog;
using Serilog.Core;
using TinyDNS.Packets;
using TinyDNS.Serialization;

namespace TinyDNS;

public static class RecursiveResolver
{
    private static readonly IPAddress RootServer = IPAddress.Parse("198.41.0.4");

    private static readonly TimeSpan UdpTimeout = TimeSpan.FromSeconds(5);

    private static readonly ILogger Logger =
        Serilog.Log.ForContext(Constants.SourceContextPropertyName, nameof(RecursiveResolver));

    private static readonly MemoryCache Cache = new MemoryCache(new MemoryCacheOptions());

    public static ValueTask<IPAddress> Resolve(string qname, CancellationToken ct = default)
    {
        return ResolveRecursive(qname.ToLowerInvariant(), RootServer, ct);
    }

    private static async ValueTask<IPAddress> ResolveRecursive(string qname, IPAddress server, CancellationToken ct)
    {
        if (Cache.TryGetValue(qname, out IPAddress cachedIpAddress))
        {
            Logger.Debug("Cache hit for {QName}", qname);
            return cachedIpAddress;
        }

        var query = new DNSQuery
        {
            Header = new DNSHeader(),
            Question = new DNSQuestion { QName = qname }
        };
        Logger.Debug("Querying {Server} with {Query}", server, query);
        var req = query.Serialize();

        using var client = new UdpClient();
        client.Client.ReceiveTimeout = (int)UdpTimeout.TotalMilliseconds;
        client.Connect(server, 53);
        var segment = req.Buffer;
        await client.SendAsync(segment.AsMemory(), ct);
        var res = await client.ReceiveAsync(ct);

        var buffer = new BinaryBuffer(res.Buffer);
        var response = DNSResponse.Deserialize(buffer);
        Logger.Debug("Deserialized response: {Response}", response);

        foreach (var answer in response.Answers)
            if (answer.ParsedRData is IPAddress ip)
            {
                Cache.Set(qname, ip, TimeSpan.FromSeconds(answer.TTL));
                return ip;
            }

        Dictionary<string, IPAddress> glueRecords = null;
        foreach (var additional in response.Additionals)
        {
            if (additional.Type == 1 && additional.ParsedRData is IPAddress glueIp)
            {
                glueRecords ??= new Dictionary<string, IPAddress>();
                glueRecords[additional.Name] = glueIp;
                Cache.Set(additional.Name, glueIp, TimeSpan.FromSeconds(additional.TTL));
            }
        }

        foreach (var authority in response.Authorities)
            if (authority.Type == 2 && authority.ParsedRData is string nsHostname)
            {
                if (glueRecords != null && glueRecords.TryGetValue(nsHostname, out var nsIp))
                {
                    return await ResolveRecursive(qname, nsIp, ct);
                }

                var resolvedNsIp = await ResolveRecursive(nsHostname, RootServer, ct);
                if (resolvedNsIp != null)
                    return await ResolveRecursive(qname, resolvedNsIp, ct);
            }

        return null;
    }
}
