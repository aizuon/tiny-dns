using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using Serilog;
using Serilog.Core;
using TinyDNS.Packets;
using TinyDNS.Serialization;

namespace TinyDNS;

public static class RecursiveResolver
{
    private static readonly IPAddress[] RootServers = new[]
    {
        IPAddress.Parse("198.41.0.4"),
        IPAddress.Parse("199.9.14.201"),
        IPAddress.Parse("192.33.4.12"),
        IPAddress.Parse("199.7.91.13"),
        IPAddress.Parse("192.203.230.10"),
        IPAddress.Parse("192.5.5.241"),
        IPAddress.Parse("192.112.36.4"),
        IPAddress.Parse("198.97.190.53"),
        IPAddress.Parse("192.36.148.17"),
        IPAddress.Parse("192.58.128.30"),
        IPAddress.Parse("193.0.14.129"),
        IPAddress.Parse("199.7.83.42"),
        IPAddress.Parse("202.12.27.33")
    };

    private static int _rootServerIndex;

    // ReSharper disable once NotAccessedField.Local — prevent GC of the timer
    private static readonly Timer CleanupTimer;

    private static readonly TimeSpan UdpTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TcpTimeout = TimeSpan.FromSeconds(7);
    private static readonly TimeSpan TlsTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan HttpsTimeout = TimeSpan.FromSeconds(10);

    public static bool UseDnsOverTls { get; set; }
    public static bool UseDnsOverHttps { get; set; }

    public static string DnsOverHttpsUrl { get; set; }

    public static IPAddress ForwardingDnsServer { get; set; }

    public static bool AllowInvalidCertificates { get; set; }

    private static readonly HttpClient HttpClient = new HttpClient
    {
        Timeout = HttpsTimeout
    };

    private static readonly ILogger Logger =
        Serilog.Log.ForContext(Constants.SourceContextPropertyName, nameof(RecursiveResolver));

    private static readonly MemoryCache Cache = new MemoryCache(new MemoryCacheOptions());

    private static readonly RateLimiter RateLimiter = new RateLimiter(
        maxQueriesPerServerPerSecond: 10,
        maxQueriesGlobalPerSecond: 100
    );

    private const uint DefaultNegativeCacheTTL = 300;
    private const int MaxCnameChainDepth = 10;
    private const int MaxRecursionDepth = 20;

    static RecursiveResolver()
    {
        CleanupTimer = new Timer(
            _ => RateLimiter.Cleanup(),
            null,
            TimeSpan.FromMinutes(1),
            TimeSpan.FromMinutes(1)
        );
    }

    public static async ValueTask<IPAddress> Resolve(string qname, CancellationToken ct = default)
    {
        Logger.Information("Starting DNS resolution for {QName}", qname);

        if (ForwardingDnsServer != null)
        {
            return await ResolveWithForwarding(qname.ToLowerInvariant(), ct);
        }

        return await ResolveWithRootFallback(qname.ToLowerInvariant(), ct, 0);
    }

    public static async ValueTask<DNSResourceRecord[]> Query(string qname, DNSRecordType qtype,
        CancellationToken ct = default)
    {
        Logger.Information("Starting DNS query for {QName} (type={QType})", qname, qtype);

        if (ForwardingDnsServer != null)
        {
            return await QueryWithForwarding(qname.ToLowerInvariant(), (ushort)qtype, ct);
        }

        return await QueryWithRootFallback(qname.ToLowerInvariant(), (ushort)qtype, ct, 0);
    }

    public static async ValueTask<string> ReverseLookup(IPAddress ipAddress, CancellationToken ct = default)
    {
        var reverseQuery = BuildReverseQuery(ipAddress);
        Logger.Information("Starting reverse DNS lookup for {IP} ({Query})", ipAddress, reverseQuery);

        var records = await QueryWithRootFallback(reverseQuery, (ushort)DNSRecordType.PTR, ct, 0);
        if (records.Length > 0 && records[0].ParsedRData is string hostname)
            return hostname;

        return null;
    }

    private static string BuildReverseQuery(IPAddress ipAddress)
    {
        var bytes = ipAddress.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
        }

        throw new NotSupportedException("IPv6 reverse lookups not yet supported");
    }

    private static IPAddress GetNextRootServer()
    {
        var index = (Interlocked.Increment(ref _rootServerIndex) & 0x7FFFFFFF) % RootServers.Length;
        return RootServers[index];
    }

    private static async ValueTask<IPAddress> ResolveWithForwarding(string qname, CancellationToken ct,
        int cnameDepth = 0)
    {
        if (cnameDepth > MaxCnameChainDepth)
        {
            Logger.Warning("CNAME chain too deep via forwarding for {QName}, aborting", qname);
            return null;
        }

        var server = ForwardingDnsServer;
        Logger.Information("Forwarding query for {QName} to {Server}", qname, server);

        var query = new DNSQuery
        {
            Header = new DNSHeader(),
            Question = new DNSQuestion { QName = qname }
        };

        var response = await SendDnsQuery(query, server, ct);

        if (response.Answers.Length > 0)
        {
            foreach (var answer in response.Answers)
            {
                if (answer.Type == 1 && answer.ParsedRData is IPAddress ip)
                {
                    Logger.Information("Resolved {QName} → {IP} via forwarding", qname, ip);
                    return ip;
                }
            }

            foreach (var answer in response.Answers)
            {
                if (answer.Type == 5 && answer.ParsedRData is string cnameTarget)
                {
                    Logger.Information("CNAME {QName} → {Target} via forwarding, following", qname, cnameTarget);
                    return await ResolveWithForwarding(cnameTarget.ToLowerInvariant(), ct, cnameDepth + 1);
                }
            }
        }

        Logger.Warning("No A record found in forwarding response for {QName}", qname);
        return null;
    }

    private static async ValueTask<DNSResourceRecord[]> QueryWithForwarding(string qname, ushort qtype,
        CancellationToken ct)
    {
        var server = ForwardingDnsServer;
        Logger.Information("Forwarding query for {QName} (type={QType}) to {Server}", qname, qtype, server);

        var query = new DNSQuery
        {
            Header = new DNSHeader(),
            Question = new DNSQuestion { QName = qname, QType = qtype }
        };

        var response = await SendDnsQuery(query, server, ct);
        Logger.Information("Received {Count} answers via forwarding for {QName}", response.Answers.Length, qname);
        return response.Answers;
    }

    private static async ValueTask<IPAddress> ResolveWithRootFallback(string qname, CancellationToken ct, int depth)
    {
        return await ResolveWithRootFallback(qname, ct, depth, new ConcurrentDictionary<string, byte>());
    }

    private static async ValueTask<IPAddress> ResolveWithRootFallback(string qname, CancellationToken ct, int depth,
        ConcurrentDictionary<string, byte> visitedCnames)
    {
        var attemptedServers = new HashSet<IPAddress>();
        var maxAttempts = Math.Min(3, RootServers.Length);

        for (var i = 0; i < maxAttempts; i++)
        {
            var rootServer = GetNextRootServer();
            if (!attemptedServers.Add(rootServer))
                continue;

            try
            {
                var result = await ResolveRecursive(qname, rootServer, ct, depth, visitedCnames);
                if (result != null)
                    return result;
            }
            catch (Exception ex) when (ex is SocketException or TimeoutException or OperationCanceledException
                                           or IOException or InvalidDataException)
            {
                Logger.Warning("Root server {Server} failed: {Error}, trying next server", rootServer, ex.Message);
            }
        }

        Logger.Warning("All root server attempts failed for {QName}", qname);
        return null;
    }

    private static async ValueTask<DNSResourceRecord[]> QueryWithRootFallback(string qname, ushort qtype,
        CancellationToken ct, int depth)
    {
        var attemptedServers = new HashSet<IPAddress>();
        var maxAttempts = Math.Min(3, RootServers.Length);

        for (var i = 0; i < maxAttempts; i++)
        {
            var rootServer = GetNextRootServer();
            if (!attemptedServers.Add(rootServer))
                continue;

            try
            {
                var result = await QueryRecursive(qname, qtype, rootServer, ct, depth);
                if (result.Length > 0)
                    return result;
            }
            catch (Exception ex) when (ex is SocketException or TimeoutException or OperationCanceledException
                                           or IOException or InvalidDataException)
            {
                Logger.Warning("Root server {Server} failed: {Error}, trying next server", rootServer, ex.Message);
            }
        }

        Logger.Warning("All root server attempts failed for {QName}", qname);
        return Array.Empty<DNSResourceRecord>();
    }

    private static async ValueTask<DNSResponse> SendDnsQuery(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        if (UseDnsOverHttps && !string.IsNullOrEmpty(DnsOverHttpsUrl))
        {
            return await SendDnsQueryOverHttps(query, ct);
        }

        if (UseDnsOverTls)
        {
            return await SendDnsQueryOverTls(query, server, ct);
        }

        var response = await SendDnsQueryOverUdp(query, server, ct);

        if (response.Header.TC == 1)
        {
            Logger.Verbose("Response truncated (TC=1) from {Server}, retrying over TCP", server);
            return await SendDnsQueryOverTcp(query, server, ct);
        }

        return response;
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverUdp(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        var req = query.Serialize();
        using var client = new UdpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(UdpTimeout);
        client.Connect(server, 53);
        var segment = req.Buffer;
        await client.SendAsync(segment.AsMemory(), cts.Token);
        var res = await client.ReceiveAsync(cts.Token);
        var buffer = new BinaryBuffer(res.Buffer);
        return DNSResponse.Deserialize(buffer);
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverTcp(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        using var tcpClient = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TcpTimeout);

        await tcpClient.ConnectAsync(server, 53, cts.Token);
        var stream = tcpClient.GetStream();

        var req = query.Serialize();
        var lengthPrefix = new byte[2];
        lengthPrefix[0] = (byte)(req.Buffer.Count >> 8);
        lengthPrefix[1] = (byte)(req.Buffer.Count & 0xFF);

        await stream.WriteAsync(lengthPrefix.AsMemory(), cts.Token);
        await stream.WriteAsync(req.Buffer.AsMemory(), cts.Token);
        await stream.FlushAsync(cts.Token);

        var lengthBuffer = new byte[2];
        var bytesRead = await stream.ReadAsync(lengthBuffer.AsMemory(), cts.Token);
        if (bytesRead != 2)
            throw new IOException("Failed to read length prefix from TCP response");

        var responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];
        var responseBuffer = new byte[responseLength];
        var totalRead = 0;

        while (totalRead < responseLength)
        {
            bytesRead = await stream.ReadAsync(responseBuffer.AsMemory(totalRead), cts.Token);
            if (bytesRead == 0)
                throw new IOException("Connection closed before full TCP response received");
            totalRead += bytesRead;
        }

        var buffer = new BinaryBuffer(responseBuffer);
        return DNSResponse.Deserialize(buffer);
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverTls(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        using var tcpClient = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TlsTimeout);

        await tcpClient.ConnectAsync(server, 853, cts.Token);

        await using var sslStream = new SslStream(
            tcpClient.GetStream(),
            false
        );

        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = server.ToString(),
            RemoteCertificateValidationCallback = ValidateServerCertificate
        };
        await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token);

        var req = query.Serialize();
        var lengthPrefix = new byte[2];
        lengthPrefix[0] = (byte)(req.Buffer.Count >> 8);
        lengthPrefix[1] = (byte)(req.Buffer.Count & 0xFF);

        await sslStream.WriteAsync(lengthPrefix.AsMemory(), cts.Token);
        await sslStream.WriteAsync(req.Buffer.AsMemory(), cts.Token);
        await sslStream.FlushAsync(cts.Token);

        var lengthBuffer = new byte[2];
        var bytesRead = await sslStream.ReadAsync(lengthBuffer.AsMemory(), cts.Token);
        if (bytesRead != 2)
            throw new IOException("Failed to read length prefix from DoT response");

        var responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];
        var responseBuffer = new byte[responseLength];
        var totalRead = 0;

        while (totalRead < responseLength)
        {
            bytesRead = await sslStream.ReadAsync(responseBuffer.AsMemory(totalRead), cts.Token);
            if (bytesRead == 0)
                throw new IOException("Connection closed before full DoT response received");
            totalRead += bytesRead;
        }

        var buffer = new BinaryBuffer(responseBuffer);
        return DNSResponse.Deserialize(buffer);
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverHttps(
        DNSQuery query,
        CancellationToken ct
    )
    {
        if (string.IsNullOrEmpty(DnsOverHttpsUrl))
            throw new InvalidOperationException("DnsOverHttpsUrl must be set when UseDnsOverHttps is enabled");

        var req = query.Serialize();
        var content = new ByteArrayContent(req.Buffer.Array!, req.Buffer.Offset, req.Buffer.Count);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");

        using var request = new HttpRequestMessage(HttpMethod.Post, DnsOverHttpsUrl)
        {
            Content = content
        };
        request.Headers.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-message"));

        using var response = await HttpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var responseBytes = await response.Content.ReadAsByteArrayAsync(ct);
        var buffer = new BinaryBuffer(responseBytes);
        return DNSResponse.Deserialize(buffer);
    }

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors
    )
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        Logger.Warning("DoT certificate validation errors: {Errors}", sslPolicyErrors);

        if (AllowInvalidCertificates)
        {
            Logger.Warning("Accepting invalid DoT certificate due to AllowInvalidCertificates=true (INSECURE)");
            return true;
        }

        if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            Logger.Error("DoT certificate validation failed: No certificate provided by server");
            return false;
        }

        if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            Logger.Error("DoT certificate validation failed: Certificate name does not match server");
            return false;
        }

        if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
        {
            Logger.Error("DoT certificate validation failed: Certificate chain errors");

            if (chain?.ChainStatus != null)
            {
                foreach (var status in chain.ChainStatus)
                {
                    Logger.Error("  Chain error: {StatusInfo} ({Status})", status.StatusInformation, status.Status);
                }
            }

            return false;
        }

        return false;
    }

    private static async ValueTask<IPAddress> ResolveRecursive(string qname, IPAddress server, CancellationToken ct,
        int depth, ConcurrentDictionary<string, byte> visitedCnames)
    {
        var indent = new string(' ', depth * 2);

        if (depth > MaxRecursionDepth)
        {
            Logger.Warning("{Indent}└─ Max recursion depth reached for {QName}, aborting", indent, qname);
            return null;
        }

        if (Cache.TryGetValue(qname, out object cachedEntry))
        {
            if (cachedEntry is NegativeCacheEntry)
            {
                Logger.Information("{Indent}└─ Negative cache hit: {QName} (does not exist)", indent, qname);
                return null;
            }

            var cachedIpAddress = (IPAddress)cachedEntry;
            Logger.Information("{Indent}└─ Cache hit: {QName} → {IP}", indent, qname, cachedIpAddress);
            return cachedIpAddress;
        }

        Logger.Information("{Indent}├─ Query: {QName} @ {Server} (depth={Depth})", indent, qname, server, depth);

        if (!RateLimiter.AllowQuery(server.ToString()))
        {
            Logger.Warning("{Indent}└─ Rate limit exceeded for {Server}, query rejected", indent, server);
            return null;
        }

        var query = new DNSQuery
        {
            Header = new DNSHeader(),
            Question = new DNSQuestion { QName = qname }
        };

        var response = await SendDnsQuery(query, server, ct);

        if (!ValidateResponse(query, response, server, indent))
            return null;

        Logger.Verbose(
            "{Indent}│  Response: RCode={RCode}, {AnswerCount} answers, {AuthCount} authorities, {AddCount} additionals",
            indent, response.Header.RCode, response.Answers.Length, response.Authorities.Length,
            response.Additionals.Length);

        if (response.Header.RCode == 2)
        {
            Logger.Warning("{Indent}└─ SERVFAIL from {Server}, server cannot process query", indent, server);
            return null;
        }

        if (response.Header.RCode == 5)
        {
            Logger.Warning("{Indent}└─ REFUSED from {Server}, server refuses to answer", indent, server);
            return null;
        }

        if (response.Header.RCode == 3)
        {
            var negativeTtl = ExtractNegativeTTL(response.Authorities);
            Logger.Information("{Indent}└─ NXDOMAIN: {QName} does not exist (TTL={TTL}s)", indent, qname, negativeTtl);
            if (negativeTtl > 0)
            {
                Cache.Set(qname, NegativeCacheEntry.Instance, TimeSpan.FromSeconds(negativeTtl));
            }

            return null;
        }

        if (response.Header.RCode == 0 && response.Answers.Length == 0 && response.Authorities.Length > 0)
        {
            bool hasNS = false;
            foreach (var auth in response.Authorities)
            {
                if (auth.Type == 2)
                {
                    hasNS = true;
                    break;
                }
            }

            if (!hasNS)
            {
                var negativeTtl = ExtractNegativeTTL(response.Authorities);
                Logger.Information("{Indent}└─ NODATA: {QName} has no A records (TTL={TTL}s)", indent, qname,
                    negativeTtl);
                if (negativeTtl > 0)
                {
                    Cache.Set(qname, NegativeCacheEntry.Instance, TimeSpan.FromSeconds(negativeTtl));
                }

                return null;
            }
        }

        foreach (var answer in response.Answers)
        {
            if (answer.Type == 5 && answer.ParsedRData is string cnameTarget)
            {
                if (depth >= MaxCnameChainDepth)
                {
                    Logger.Warning("{Indent}└─ CNAME chain too deep for {QName}, aborting", indent, qname);
                    return null;
                }

                var cnameTargetLower = cnameTarget.ToLowerInvariant();
                if (!visitedCnames.TryAdd(cnameTargetLower, 0))
                {
                    Logger.Warning("{Indent}└─ CNAME loop detected: {QName} → {Target} (already visited)", indent,
                        qname, cnameTarget);
                    return null;
                }

                visitedCnames.TryAdd(qname.ToLowerInvariant(), 0);
                Logger.Information("{Indent}├─ CNAME: {QName} → {Target}", indent, qname, cnameTarget);

                var targetIp = await ResolveWithRootFallback(cnameTargetLower, ct, depth + 1, visitedCnames);
                if (targetIp != null)
                {
                    Logger.Information("{Indent}└─ Resolved via CNAME: {QName} → {IP}", indent, qname, targetIp);
                    if (answer.TTL > 0)
                    {
                        Cache.Set(qname, targetIp, TimeSpan.FromSeconds(answer.TTL));
                    }
                }

                return targetIp;
            }
        }

        foreach (var answer in response.Answers)
        {
            if (answer.ParsedRData is IPAddress ip)
            {
                Logger.Information("{Indent}└─ Resolved: {QName} → {IP} (TTL={TTL}s)",
                    indent, qname, ip, answer.TTL);
                if (answer.TTL > 0)
                {
                    Cache.Set(qname, ip, TimeSpan.FromSeconds(answer.TTL));
                }

                return ip;
            }
        }

        Dictionary<string, IPAddress> glueRecords = null;
        foreach (var additional in response.Additionals)
        {
            if (additional.Type == 1 && additional.ParsedRData is IPAddress glueIp)
            {
                glueRecords ??= new Dictionary<string, IPAddress>();
                glueRecords[additional.Name] = glueIp;
                Logger.Verbose("{Indent}│  Glue: {NSName} → {IP}", indent, additional.Name, glueIp);
                if (additional.TTL > 0)
                {
                    Cache.Set(additional.Name, glueIp, TimeSpan.FromSeconds(additional.TTL));
                }
            }
        }

        var nameserverIps = new HashSet<IPAddress>();
        var nameserversToResolve = new List<string>();

        foreach (var authority in response.Authorities)
        {
            if (authority.Type == 2 && authority.ParsedRData is string nsHostname)
            {
                Logger.Information("{Indent}├─ Referral: {NSName}", indent, nsHostname);

                if (glueRecords != null && glueRecords.TryGetValue(nsHostname, out var nsIp))
                {
                    Logger.Information("{Indent}│  Using glue record: {NSName} → {IP}", indent, nsHostname, nsIp);
                    nameserverIps.Add(nsIp);
                }
                else
                {
                    nameserversToResolve.Add(nsHostname);
                }
            }
        }

        foreach (var nsHostname in nameserversToResolve)
        {
            Logger.Information("{Indent}│  Resolving nameserver: {NSName}", indent, nsHostname);
            var resolvedNsIp = await ResolveWithRootFallback(nsHostname, ct, depth + 1);
            if (resolvedNsIp != null)
                nameserverIps.Add(resolvedNsIp);
        }

        if (nameserverIps.Count == 0)
        {
            Logger.Warning("{Indent}└─ No usable nameservers for {QName}", indent, qname);
            return null;
        }

        var nameserverList = nameserverIps.ToList();

        Logger.Information("{Indent}├─ Querying {Count} nameserver(s) in parallel", indent, nameserverList.Count);
        var result = await QueryNameserversInParallel(
            nameserverList,
            (ns, token) => ResolveRecursive(qname, ns, token, depth + 1, visitedCnames),
            ct
        );

        if (result != null)
            return result;

        Logger.Warning("{Indent}└─ No usable response for {QName}", indent, qname);
        return null;
    }

    private static async ValueTask<DNSResourceRecord[]> QueryRecursive(string qname, ushort qtype, IPAddress server,
        CancellationToken ct, int depth)
    {
        var indent = new string(' ', depth * 2);

        if (depth > MaxRecursionDepth)
        {
            Logger.Warning("{Indent}└─ Max recursion depth reached for {QName}, aborting", indent, qname);
            return Array.Empty<DNSResourceRecord>();
        }

        Logger.Information("{Indent}├─ Query: {QName} (type={QType}) @ {Server} (depth={Depth})",
            indent, qname, qtype, server, depth);

        if (!RateLimiter.AllowQuery(server.ToString()))
        {
            Logger.Warning("{Indent}└─ Rate limit exceeded for {Server}, query rejected", indent, server);
            return Array.Empty<DNSResourceRecord>();
        }

        var query = new DNSQuery
        {
            Header = new DNSHeader(),
            Question = new DNSQuestion { QName = qname, QType = qtype }
        };

        var response = await SendDnsQuery(query, server, ct);

        if (!ValidateResponse(query, response, server, indent))
            return Array.Empty<DNSResourceRecord>();

        Logger.Verbose(
            "{Indent}│  Response: RCode={RCode}, {AnswerCount} answers, {AuthCount} authorities, {AddCount} additionals",
            indent, response.Header.RCode, response.Answers.Length, response.Authorities.Length,
            response.Additionals.Length);

        if (response.Header.RCode == 2)
        {
            Logger.Warning("{Indent}└─ SERVFAIL from {Server}, server cannot process query", indent, server);
            return Array.Empty<DNSResourceRecord>();
        }

        if (response.Header.RCode == 5)
        {
            Logger.Warning("{Indent}└─ REFUSED from {Server}, server refuses to answer", indent, server);
            return Array.Empty<DNSResourceRecord>();
        }

        if (response.Header.RCode == 3)
        {
            var negativeTtl = ExtractNegativeTTL(response.Authorities);
            Logger.Information("{Indent}└─ NXDOMAIN: {QName} does not exist (TTL={TTL}s)", indent, qname, negativeTtl);
            return Array.Empty<DNSResourceRecord>();
        }

        if (response.Answers.Length > 0)
        {
            Logger.Information("{Indent}└─ Found {Count} answer(s) for {QName}", indent, response.Answers.Length,
                qname);
            return response.Answers;
        }

        Dictionary<string, IPAddress> glueRecords = null;
        foreach (var additional in response.Additionals)
        {
            if (additional.Type == 1 && additional.ParsedRData is IPAddress glueIp)
            {
                glueRecords ??= new Dictionary<string, IPAddress>();
                glueRecords[additional.Name] = glueIp;
                Logger.Verbose("{Indent}│  Glue: {NSName} → {IP}", indent, additional.Name, glueIp);
            }
        }

        var nameserverIps = new HashSet<IPAddress>();
        var nameserversToResolve = new List<string>();

        foreach (var authority in response.Authorities)
        {
            if (authority.Type == 2 && authority.ParsedRData is string nsHostname)
            {
                Logger.Information("{Indent}├─ Referral: {NSName}", indent, nsHostname);

                if (glueRecords != null && glueRecords.TryGetValue(nsHostname, out var nsIp))
                {
                    Logger.Information("{Indent}│  Using glue record: {NSName} → {IP}", indent, nsHostname, nsIp);
                    nameserverIps.Add(nsIp);
                }
                else
                {
                    nameserversToResolve.Add(nsHostname);
                }
            }
        }

        foreach (var nsHostname in nameserversToResolve)
        {
            Logger.Information("{Indent}│  Resolving nameserver: {NSName}", indent, nsHostname);
            var resolvedNsIp = await ResolveWithRootFallback(nsHostname, ct, depth + 1);
            if (resolvedNsIp != null)
                nameserverIps.Add(resolvedNsIp);
        }

        if (nameserverIps.Count == 0)
        {
            Logger.Warning("{Indent}└─ No usable nameservers for {QName}", indent, qname);
            return Array.Empty<DNSResourceRecord>();
        }

        var nameserverList = nameserverIps.ToList();

        Logger.Information("{Indent}├─ Querying {Count} nameserver(s) in parallel", indent, nameserverList.Count);
        var result = await QueryNameserversInParallel(
            nameserverList,
            (ns, token) => QueryRecursive(qname, qtype, ns, token, depth + 1),
            ct
        );

        if (result != null && result.Length > 0)
            return result;

        Logger.Warning("{Indent}└─ No usable response for {QName}", indent, qname);
        return Array.Empty<DNSResourceRecord>();
    }

    private static async ValueTask<T> QueryNameserversInParallel<T>(
        List<IPAddress> nameservers,
        Func<IPAddress, CancellationToken, ValueTask<T>> queryFunc,
        CancellationToken ct
    ) where T : class
    {
        if (nameservers.Count == 1)
        {
            return await queryFunc(nameservers[0], ct);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = new List<Task<T>>(nameservers.Count);
        foreach (var ns in nameservers)
        {
            var capturedNs = ns;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    return await queryFunc(capturedNs, cts.Token);
                }
                catch (Exception ex) when (ex is SocketException or TimeoutException or OperationCanceledException
                                               or IOException or InvalidDataException)
                {
                    return null;
                }
            }, cts.Token));
        }

        while (tasks.Count > 0)
        {
            var completedTask = await Task.WhenAny(tasks);
            var result = await completedTask;

            if (result != null)
            {
                await cts.CancelAsync();
                return result;
            }

            tasks.Remove(completedTask);
        }

        return null;
    }

    private static uint ExtractNegativeTTL(DNSResourceRecord[] authorities)
    {
        foreach (var auth in authorities)
        {
            if (auth.Type == 6 && auth.ParsedRData is SOARecord soa)
            {
                return soa.Minimum;
            }
        }

        return DefaultNegativeCacheTTL;
    }

    private static bool ValidateResponse(DNSQuery query, DNSResponse response, IPAddress server, string indent)
    {
        if (response.Header.QR != 1)
        {
            Logger.Warning("{Indent}└─ Invalid response from {Server}: QR bit not set (not a response)",
                indent, server);
            return false;
        }

        if (response.Header.Id != query.Header.Id)
        {
            Logger.Warning(
                "{Indent}└─ Response ID mismatch from {Server}: expected {Expected}, got {Actual} (possible spoofing)",
                indent, server, query.Header.Id, response.Header.Id);
            return false;
        }

        if (!string.Equals(response.Question.QName, query.Question.QName, StringComparison.OrdinalIgnoreCase))
        {
            Logger.Warning(
                "{Indent}└─ Question name mismatch from {Server}: expected {Expected}, got {Actual} (possible spoofing)",
                indent, server, query.Question.QName, response.Question.QName);
            return false;
        }

        if (response.Question.QType != query.Question.QType)
        {
            Logger.Warning(
                "{Indent}└─ Question type mismatch from {Server}: expected {Expected}, got {Actual}",
                indent, server, query.Question.QType, response.Question.QType);
            return false;
        }

        if (response.Header.Questions != 1)
        {
            Logger.Warning("{Indent}└─ Invalid question count from {Server}: {Count} (expected 1)",
                indent, server, response.Header.Questions);
            return false;
        }

        return true;
    }
}
