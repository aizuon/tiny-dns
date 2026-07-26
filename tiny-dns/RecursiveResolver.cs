using System.Buffers.Binary;
using System.Globalization;
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
    private static readonly IPAddress[] RootServers =
    [
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
    ];

    private static int _rootServerIndex;

    // ReSharper disable once NotAccessedField.Local — prevent GC of the timer
    private static readonly Timer CleanupTimer;

    private static readonly TimeSpan UdpTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TcpTimeout = TimeSpan.FromSeconds(7);
    private static readonly TimeSpan TlsTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan HttpsTimeout = TimeSpan.FromSeconds(10);

    public static bool UseDnsOverTls { get; set; }
    public static bool UseDnsOverHttps { get; set; }

    public static string? DnsOverHttpsUrl { get; set; }

    public static IPAddress? ForwardingDnsServer { get; set; }

    public static string? DnsOverTlsHostName { get; set; }

    public static bool AllowInvalidCertificates { get; set; }

    private static readonly HttpClient HttpClient = new HttpClient
    {
        Timeout = HttpsTimeout,
        MaxResponseContentBufferSize = ushort.MaxValue
    };

    private static readonly ILogger Logger =
        Serilog.Log.ForContext(Constants.SourceContextPropertyName, nameof(RecursiveResolver));

    private static readonly MemoryCache Cache = new MemoryCache(new MemoryCacheOptions());

    private static readonly RateLimiter RateLimiter = new RateLimiter(
        maxQueriesPerServerPerSecond: 10,
        maxQueriesGlobalPerSecond: 100
    );

    private const int MaxCnameChainDepth = 10;
    private const int MaxRecursionDepth = 20;
    private const int MaxParallelNameservers = 2;

    static RecursiveResolver()
    {
        CleanupTimer = new Timer(
            _ => RateLimiter.Cleanup(),
            null,
            TimeSpan.FromMinutes(1),
            TimeSpan.FromMinutes(1)
        );
    }

    public static async ValueTask<IPAddress?> Resolve(string qname, CancellationToken ct = default)
    {
        qname = NormalizeQueryName(qname);
        Logger.Information("Starting DNS resolution for {QName}", qname);

        if (Cache.TryGetValue(qname, out object? cachedEntry))
        {
            if (cachedEntry is IPAddress cachedAddress)
            {
                Logger.Information("Resolved {QName} → {IP} from cache", qname, cachedAddress);
                return cachedAddress;
            }
            if (cachedEntry is NegativeCacheEntry)
                return null;
        }

        if (UseDnsOverTls && ForwardingDnsServer is null)
        {
            throw new InvalidOperationException(
                "DNS-over-TLS requires ForwardingDnsServer because authoritative DNS servers do not generally expose DoT.");
        }

        var result = ForwardingDnsServer is not null
            ? await ResolveWithForwarding(qname, ct)
            : await ResolveWithRootFallback(qname, ct, 0);

        if (result is not null)
            Logger.Information("Completed DNS resolution: {QName} → {IP}", qname, result);

        return result;
    }

    public static async ValueTask<DNSResourceRecord[]> Query(string qname, DNSRecordType qtype,
        CancellationToken ct = default)
    {
        qname = NormalizeQueryName(qname);
        Logger.Information("Starting DNS query for {QName} (type={QType})", qname, qtype);

        if (UseDnsOverTls && ForwardingDnsServer is null)
        {
            throw new InvalidOperationException(
                "DNS-over-TLS requires ForwardingDnsServer because authoritative DNS servers do not generally expose DoT.");
        }

        var records = ForwardingDnsServer is not null
            ? await QueryWithForwarding(qname, (ushort)qtype, ct)
            : await QueryWithRootFallback(qname, (ushort)qtype, ct, 0);

        Logger.Information("Completed DNS query for {QName}: {Count} answer(s)", qname, records.Length);
        return records;
    }

    public static async ValueTask<string?> ReverseLookup(IPAddress ipAddress, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        var reverseQuery = BuildReverseQuery(ipAddress);
        Logger.Information("Starting reverse DNS lookup for {IP} ({Query})", ipAddress, reverseQuery);

        var records = await Query(reverseQuery, DNSRecordType.PTR, ct);
        foreach (var record in records)
        {
            if (record.Type == (ushort)DNSRecordType.PTR && record.ParsedRData is string hostname)
                return hostname;
        }

        return null;
    }

    internal static string BuildReverseQuery(IPAddress ipAddress)
    {
        if (ipAddress.IsIPv4MappedToIPv6)
            ipAddress = ipAddress.MapToIPv4();

        var bytes = ipAddress.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
        }

        var builder = new System.Text.StringBuilder(bytes.Length * 4 + "ip6.arpa".Length);
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            builder.Append((bytes[i] & 0x0F).ToString("x", CultureInfo.InvariantCulture));
            builder.Append('.');
            builder.Append((bytes[i] >> 4).ToString("x", CultureInfo.InvariantCulture));
            builder.Append('.');
        }

        return builder.Append("ip6.arpa").ToString();
    }

    private static IPAddress GetNextRootServer()
    {
        var index = ((Interlocked.Increment(ref _rootServerIndex) - 1) & 0x7FFFFFFF) % RootServers.Length;
        return RootServers[index];
    }

    private static async ValueTask<IPAddress?> ResolveWithForwarding(string qname, CancellationToken ct,
        int cnameDepth = 0)
    {
        if (cnameDepth >= MaxCnameChainDepth)
        {
            Logger.Warning("CNAME chain too deep via forwarding for {QName}, aborting", qname);
            return null;
        }

        var server = ForwardingDnsServer ??
                     throw new InvalidOperationException("A forwarding DNS server has not been configured.");
        Logger.Debug("Forwarding query for {QName} to {Server}", qname, server);

        var query = CreateQuery(qname, (ushort)DNSRecordType.A);

        var response = await SendDnsQuery(query, server, ct);
        if (!ValidateResponse(query, response, server, string.Empty))
            return null;

        if (response.Header.RCode == 3)
        {
            var negativeTtl = ExtractNegativeTTL(response.Authorities);
            if (negativeTtl > 0)
                Cache.Set(qname, NegativeCacheEntry.Instance, TimeSpan.FromSeconds(negativeTtl));

            return null;
        }

        if (response.Header.RCode != 0)
            return null;

        if (response.Answers.Length > 0)
        {
            foreach (var answer in response.Answers)
            {
                if (answer.Type == (ushort)DNSRecordType.A &&
                    answer.Class == 1 &&
                    string.Equals(answer.Name, qname, StringComparison.OrdinalIgnoreCase) &&
                    answer.ParsedRData is IPAddress ip)
                {
                    Logger.Debug("Resolved {QName} → {IP} via forwarding", qname, ip);
                    if (answer.TTL > 0)
                        Cache.Set(qname, ip, TimeSpan.FromSeconds(answer.TTL));

                    return ip;
                }
            }

            foreach (var answer in response.Answers)
            {
                if (answer.Type == (ushort)DNSRecordType.CNAME &&
                    answer.Class == 1 &&
                    string.Equals(answer.Name, qname, StringComparison.OrdinalIgnoreCase) &&
                    answer.ParsedRData is string cnameTarget)
                {
                    var normalizedTarget = NormalizeQueryName(cnameTarget);
                    foreach (var targetAnswer in response.Answers)
                    {
                        if (targetAnswer.Type != (ushort)DNSRecordType.A ||
                            targetAnswer.Class != 1 ||
                            !string.Equals(targetAnswer.Name, normalizedTarget, StringComparison.OrdinalIgnoreCase) ||
                            targetAnswer.ParsedRData is not IPAddress includedTargetIp)
                        {
                            continue;
                        }

                        var ttl = Math.Min(answer.TTL, targetAnswer.TTL);
                        if (ttl > 0)
                            Cache.Set(qname, includedTargetIp, TimeSpan.FromSeconds(ttl));

                        Logger.Debug("Resolved {QName} → {IP} from forwarded CNAME answers", qname,
                            includedTargetIp);
                        return includedTargetIp;
                    }

                    Logger.Debug("CNAME {QName} → {Target} via forwarding, following", qname, cnameTarget);
                    var targetIp = await ResolveWithForwarding(normalizedTarget, ct, cnameDepth + 1);
                    return targetIp;
                }
            }
        }

        Logger.Warning("No A record found in forwarding response for {QName}", qname);
        return null;
    }

    private static async ValueTask<DNSResourceRecord[]> QueryWithForwarding(string qname, ushort qtype,
        CancellationToken ct)
    {
        var server = ForwardingDnsServer ??
                     throw new InvalidOperationException("A forwarding DNS server has not been configured.");
        Logger.Debug("Forwarding query for {QName} (type={QType}) to {Server}", qname, qtype, server);

        var query = CreateQuery(qname, qtype);

        var response = await SendDnsQuery(query, server, ct);
        if (!ValidateResponse(query, response, server, string.Empty) || response.Header.RCode != 0)
            return [];
        Logger.Debug("Received {Count} answers via forwarding for {QName}", response.Answers.Length, qname);
        return response.Answers;
    }

    private static async ValueTask<IPAddress?> ResolveWithRootFallback(string qname, CancellationToken ct, int depth)
    {
        return await ResolveWithRootFallback(qname, ct, depth, 0,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    private static async ValueTask<IPAddress?> ResolveWithRootFallback(
        string qname,
        CancellationToken ct,
        int depth,
        int cnameDepth,
        HashSet<string> visitedCnames)
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
                var result = await ResolveRecursive(
                    qname,
                    rootServer,
                    ct,
                    depth,
                    cnameDepth,
                    new HashSet<string>(visitedCnames, StringComparer.OrdinalIgnoreCase));
                if (result != null)
                    return result;

                if (Cache.TryGetValue(qname, out object? cachedEntry) && cachedEntry is NegativeCacheEntry)
                    return null;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested && IsTransientNetworkFailure(ex))
            {
                Logger.Warning("Root server {Server} failed: {Error}, trying next server", rootServer, ex.Message);
            }
        }

        if (depth == 0)
            Logger.Warning("All root server attempts failed for {QName}", qname);
        else
            Logger.Debug("All root server attempts failed for {QName}", qname);
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
            catch (Exception ex) when (!ct.IsCancellationRequested && IsTransientNetworkFailure(ex))
            {
                Logger.Warning("Root server {Server} failed: {Error}, trying next server", rootServer, ex.Message);
            }
        }

        if (depth == 0)
            Logger.Warning("All root server attempts failed for {QName}", qname);
        else
            Logger.Debug("All root server attempts failed for {QName}", qname);
        return Array.Empty<DNSResourceRecord>();
    }

    private static async ValueTask<DNSResponse> SendDnsQuery(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        if (UseDnsOverHttps)
        {
            if (string.IsNullOrWhiteSpace(DnsOverHttpsUrl))
                throw new InvalidOperationException("DnsOverHttpsUrl must be set when DNS-over-HTTPS is enabled.");

            return await SendDnsQueryOverHttps(query, ct);
        }

        if (UseDnsOverTls)
        {
            return await SendDnsQueryOverTls(query, server, ct);
        }

        var response = await SendDnsQueryOverUdp(query, server, ct);

        if (response.Header.TC == 1)
        {
            if (response.Header.QR != 1 || response.Header.Id != query.Header.Id)
                throw new InvalidDataException("Truncated UDP response has an invalid DNS header.");

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
        using var client = new UdpClient(server.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(UdpTimeout);
        client.Connect(server, 53);
        var segment = req.Buffer;
        await client.SendAsync(segment.AsMemory(), cts.Token);
        var res = await client.ReceiveAsync(cts.Token);
        var buffer = new BinaryBuffer(res.Buffer);
        try
        {
            return DNSResponse.Deserialize(buffer);
        }
        catch (InvalidDataException)
        {
            buffer.ReadOffset = 0;
            var header = DNSHeader.Deserialize(buffer);
            if (header.TC != 1 || header.QR != 1 || header.Id != query.Header.Id)
                throw;

            return new DNSResponse { Header = header };
        }
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverTcp(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        using var tcpClient = new TcpClient(server.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TcpTimeout);

        await tcpClient.ConnectAsync(server, 53, cts.Token);
        return await SendLengthPrefixedQuery(query, tcpClient.GetStream(), cts.Token, "TCP");
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverTls(
        DNSQuery query,
        IPAddress server,
        CancellationToken ct
    )
    {
        using var tcpClient = new TcpClient(server.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TlsTimeout);

        await tcpClient.ConnectAsync(server, 853, cts.Token);

        await using var sslStream = new SslStream(
            tcpClient.GetStream(),
            false
        );

        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = string.IsNullOrWhiteSpace(DnsOverTlsHostName)
                ? server.ToString()
                : DnsOverTlsHostName,
            RemoteCertificateValidationCallback = ValidateServerCertificate
        };
        await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token);

        return await SendLengthPrefixedQuery(query, sslStream, cts.Token, "DoT");
    }

    private static async ValueTask<DNSResponse> SendDnsQueryOverHttps(
        DNSQuery query,
        CancellationToken ct
    )
    {
        if (string.IsNullOrWhiteSpace(DnsOverHttpsUrl))
            throw new InvalidOperationException("DnsOverHttpsUrl must be set when UseDnsOverHttps is enabled");
        if (!Uri.TryCreate(DnsOverHttpsUrl, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("DnsOverHttpsUrl must be an absolute HTTPS URL.");
        }

        var req = query.Serialize();
        var content = new ByteArrayContent(req.Buffer.Array!, req.Buffer.Offset, req.Buffer.Count);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = content
        };
        request.Headers.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-message"));

        using var response = await HttpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            ct);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength > ushort.MaxValue)
            throw new InvalidDataException("DNS-over-HTTPS response exceeds the DNS message size limit.");

        var responseBytes = await ReadDnsOverHttpsResponse(response.Content, ct);

        var buffer = new BinaryBuffer(responseBytes);
        return DNSResponse.Deserialize(buffer);
    }

    private static async ValueTask<byte[]> ReadDnsOverHttpsResponse(HttpContent content, CancellationToken ct)
    {
        await using var responseStream = await content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream(content.Headers.ContentLength is > 0 and <= ushort.MaxValue
            ? (int)content.Headers.ContentLength.Value
            : 512);
        var chunk = new byte[8192];

        while (true)
        {
            var bytesRead = await responseStream.ReadAsync(chunk, ct);
            if (bytesRead == 0)
                return output.ToArray();

            if (output.Length + bytesRead > ushort.MaxValue)
                throw new InvalidDataException("DNS-over-HTTPS response exceeds the DNS message size limit.");

            output.Write(chunk, 0, bytesRead);
        }
    }

    internal static async ValueTask<DNSResponse> SendLengthPrefixedQuery(
        DNSQuery query,
        Stream stream,
        CancellationToken ct,
        string transportName)
    {
        var request = query.Serialize();
        if (request.Buffer.Count > ushort.MaxValue)
            throw new InvalidOperationException("DNS query exceeds the maximum TCP message size.");

        var lengthPrefix = new byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, (ushort)request.Buffer.Count);

        await stream.WriteAsync(lengthPrefix, ct);
        await stream.WriteAsync(request.Buffer.AsMemory(), ct);
        await stream.FlushAsync(ct);

        await stream.ReadExactlyAsync(lengthPrefix, ct);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
        if (responseLength == 0)
            throw new InvalidDataException($"{transportName} returned an empty DNS message.");

        var responseBytes = new byte[responseLength];
        await stream.ReadExactlyAsync(responseBytes, ct);
        return DNSResponse.Deserialize(new BinaryBuffer(responseBytes));
    }

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
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

    private static async ValueTask<IPAddress?> ResolveRecursive(
        string qname,
        IPAddress server,
        CancellationToken ct,
        int depth,
        int cnameDepth,
        HashSet<string> visitedCnames)
    {
        var indent = new string(' ', depth * 2);

        if (depth > MaxRecursionDepth)
        {
            Logger.Warning("{Indent}└─ Max recursion depth reached for {QName}, aborting", indent, qname);
            return null;
        }

        if (Cache.TryGetValue(qname, out object? cachedEntry))
        {
            if (cachedEntry is NegativeCacheEntry)
            {
                Logger.Debug("{Indent}└─ Negative cache hit: {QName} (does not exist)", indent, qname);
                return null;
            }

            if (cachedEntry is IPAddress cachedIpAddress)
            {
                Logger.Debug("{Indent}└─ Cache hit: {QName} → {IP}", indent, qname, cachedIpAddress);
                return cachedIpAddress;
            }
        }

        Logger.Debug("{Indent}├─ Query: {QName} @ {Server} (depth={Depth})", indent, qname, server, depth);

        if (!RateLimiter.AllowQuery(server.ToString()))
        {
            Logger.Debug("{Indent}└─ Rate limit exceeded for {Server}, query rejected", indent, server);
            return null;
        }

        var query = CreateQuery(qname, (ushort)DNSRecordType.A);

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
            Logger.Debug("{Indent}└─ NXDOMAIN: {QName} does not exist (TTL={TTL}s)", indent, qname, negativeTtl);
            if (negativeTtl > 0 && CanTrustNegativeResponse(response))
            {
                Cache.Set(qname, NegativeCacheEntry.Instance, TimeSpan.FromSeconds(negativeTtl));
            }

            return null;
        }

        if (response.Header.RCode != 0)
        {
            Logger.Warning("{Indent}└─ DNS error RCode={RCode} from {Server}", indent, response.Header.RCode, server);
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
                Logger.Debug("{Indent}└─ NODATA: {QName} has no A records (TTL={TTL}s)", indent, qname,
                    negativeTtl);
                if (negativeTtl > 0 && CanTrustNegativeResponse(response))
                {
                    Cache.Set(qname, NegativeCacheEntry.Instance, TimeSpan.FromSeconds(negativeTtl));
                }

                return null;
            }
        }

        foreach (var answer in response.Answers)
        {
            if (answer.Type == (ushort)DNSRecordType.A &&
                answer.Class == 1 &&
                string.Equals(answer.Name, qname, StringComparison.OrdinalIgnoreCase) &&
                answer.ParsedRData is IPAddress ip)
            {
                Logger.Debug("{Indent}└─ Resolved: {QName} → {IP} (TTL={TTL}s)",
                    indent, qname, ip, answer.TTL);
                if (answer.TTL > 0)
                    Cache.Set(qname, ip, TimeSpan.FromSeconds(answer.TTL));

                return ip;
            }
        }

        foreach (var answer in response.Answers)
        {
            if (answer.Type == (ushort)DNSRecordType.CNAME &&
                string.Equals(answer.Name, qname, StringComparison.OrdinalIgnoreCase) &&
                answer.ParsedRData is string cnameTarget)
            {
                if (cnameDepth >= MaxCnameChainDepth)
                {
                    Logger.Warning("{Indent}└─ CNAME chain too deep for {QName}, aborting", indent, qname);
                    return null;
                }

                var cnameTargetLower = NormalizeQueryName(cnameTarget);
                visitedCnames.Add(qname);
                if (!visitedCnames.Add(cnameTargetLower))
                {
                    Logger.Warning("{Indent}└─ CNAME loop detected: {QName} → {Target} (already visited)", indent,
                        qname, cnameTarget);
                    return null;
                }

                Logger.Debug("{Indent}├─ CNAME: {QName} → {Target}", indent, qname, cnameTarget);

                foreach (var targetAnswer in response.Answers)
                {
                    if (targetAnswer.Type != (ushort)DNSRecordType.A ||
                        targetAnswer.Class != 1 ||
                        !string.Equals(targetAnswer.Name, cnameTargetLower, StringComparison.OrdinalIgnoreCase) ||
                        targetAnswer.ParsedRData is not IPAddress includedTargetIp)
                    {
                        continue;
                    }

                    var ttl = Math.Min(answer.TTL, targetAnswer.TTL);
                    if (ttl > 0)
                        Cache.Set(qname, includedTargetIp, TimeSpan.FromSeconds(ttl));

                    Logger.Debug("{Indent}└─ Resolved from included CNAME answer: {QName} → {IP}",
                        indent, qname, includedTargetIp);
                    return includedTargetIp;
                }

                var targetIp = await ResolveWithRootFallback(
                    cnameTargetLower,
                    ct,
                    depth + 1,
                    cnameDepth + 1,
                    visitedCnames);
                if (targetIp != null)
                {
                    Logger.Debug("{Indent}└─ Resolved via CNAME: {QName} → {IP}", indent, qname, targetIp);
                }

                return targetIp;
            }
        }

        foreach (var answer in response.Answers)
        {
            if (answer.Type == (ushort)DNSRecordType.A && answer.Class == 1 &&
                answer.ParsedRData is IPAddress)
            {
                Logger.Warning("{Indent}│  Ignoring unrelated A answer for {AnswerName}", indent, answer.Name);
            }
        }

        var nameserverList = await GetNameserverAddresses(response, server, ct, depth, indent);
        if (nameserverList.Count == 0)
        {
            Logger.Debug("{Indent}└─ No usable nameservers for {QName}", indent, qname);
            return null;
        }

        Logger.Debug("{Indent}├─ Querying {Count} nameserver(s) in parallel", indent, nameserverList.Count);
        var result = await QueryNameserversInParallel(
            nameserverList,
            (ns, token) => ResolveRecursive(
                qname,
                ns,
                token,
                depth + 1,
                cnameDepth,
                new HashSet<string>(visitedCnames, StringComparer.OrdinalIgnoreCase)),
            static result => result is not null,
            ct
        );

        if (result != null)
            return result;

        Logger.Debug("{Indent}└─ No usable response for {QName}", indent, qname);
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

        Logger.Debug("{Indent}├─ Query: {QName} (type={QType}) @ {Server} (depth={Depth})",
            indent, qname, qtype, server, depth);

        if (!RateLimiter.AllowQuery(server.ToString()))
        {
            Logger.Debug("{Indent}└─ Rate limit exceeded for {Server}, query rejected", indent, server);
            return Array.Empty<DNSResourceRecord>();
        }

        var query = CreateQuery(qname, qtype);

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
            Logger.Debug("{Indent}└─ NXDOMAIN: {QName} does not exist (TTL={TTL}s)", indent, qname, negativeTtl);
            return Array.Empty<DNSResourceRecord>();
        }

        if (response.Header.RCode != 0)
        {
            Logger.Warning("{Indent}└─ DNS error RCode={RCode} from {Server}", indent, response.Header.RCode, server);
            return [];
        }

        if (response.Answers.Length > 0)
        {
            Logger.Debug("{Indent}└─ Found {Count} answer(s) for {QName}", indent, response.Answers.Length,
                qname);
            return response.Answers;
        }

        var nameserverList = await GetNameserverAddresses(response, server, ct, depth, indent);
        if (nameserverList.Count == 0)
        {
            Logger.Debug("{Indent}└─ No usable nameservers for {QName}", indent, qname);
            return Array.Empty<DNSResourceRecord>();
        }

        Logger.Debug("{Indent}├─ Querying {Count} nameserver(s) in parallel", indent, nameserverList.Count);
        var result = await QueryNameserversInParallel(
            nameserverList,
            async (ns, token) => await QueryRecursive(qname, qtype, ns, token, depth + 1),
            static records => records is { Length: > 0 },
            ct
        );

        if (result != null && result.Length > 0)
            return result;

        Logger.Debug("{Indent}└─ No usable response for {QName}", indent, qname);
        return Array.Empty<DNSResourceRecord>();
    }

    private static async ValueTask<List<IPAddress>> GetNameserverAddresses(
        DNSResponse response,
        IPAddress sourceServer,
        CancellationToken ct,
        int depth,
        string indent)
    {
        Dictionary<string, IPAddress>? glueRecords = null;
        foreach (var additional in response.Additionals)
        {
            if (additional.Type != (ushort)DNSRecordType.A ||
                additional.Class != 1 ||
                additional.ParsedRData is not IPAddress glueIp)
            {
                continue;
            }

            glueRecords ??= new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);
            glueRecords[additional.Name] = glueIp;
            Logger.Verbose("{Indent}│  Glue: {NSName} → {IP}", indent, additional.Name, glueIp);
        }

        var nameserverIps = new HashSet<IPAddress>();
        var nameserversToResolve = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var authority in response.Authorities)
        {
            if (authority.Type != (ushort)DNSRecordType.NS ||
                authority.Class != 1 ||
                authority.ParsedRData is not string nsHostname)
            {
                continue;
            }

            Logger.Debug("{Indent}├─ Referral: {NSName}", indent, nsHostname);
            var canUseGlue = IsRootServer(sourceServer) || IsSubdomainOrEqual(nsHostname, authority.Name);
            if (canUseGlue && glueRecords?.TryGetValue(nsHostname, out var nsIp) == true)
            {
                Logger.Debug("{Indent}│  Using glue record: {NSName} → {IP}", indent, nsHostname, nsIp);
                nameserverIps.Add(nsIp);
            }
            else
            {
                nameserversToResolve.Add(nsHostname);
            }
        }

        foreach (var nsHostname in nameserversToResolve)
        {
            if (nameserverIps.Count >= MaxParallelNameservers)
                break;

            Logger.Debug("{Indent}│  Resolving nameserver: {NSName}", indent, nsHostname);
            var resolvedNsIp = await ResolveWithRootFallback(nsHostname, ct, depth + 1);
            if (resolvedNsIp is not null)
                nameserverIps.Add(resolvedNsIp);
        }

        return nameserverIps.ToList();
    }

    internal static async ValueTask<T?> QueryNameserversInParallel<T>(
        List<IPAddress> nameservers,
        Func<IPAddress, CancellationToken, ValueTask<T?>> queryFunc,
        Func<T?, bool> isSuccessful,
        CancellationToken ct
    ) where T : class
    {
        var candidates = nameservers.Count <= MaxParallelNameservers
            ? nameservers
            : nameservers.GetRange(0, MaxParallelNameservers);

        if (candidates.Count == 1)
        {
            var result = await queryFunc(candidates[0], ct);
            return isSuccessful(result) ? result : null;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = new List<Task<T?>>(candidates.Count);
        foreach (var ns in candidates)
        {
            tasks.Add(ExecuteQuery(ns));
        }

        while (tasks.Count > 0)
        {
            var completedTask = await Task.WhenAny(tasks);
            var result = await completedTask;

            if (isSuccessful(result))
            {
                await cts.CancelAsync();
                return result;
            }

            tasks.Remove(completedTask);
        }

        return null;

        async Task<T?> ExecuteQuery(IPAddress nameserver)
        {
            try
            {
                return await queryFunc(nameserver, cts.Token);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested && IsTransientNetworkFailure(ex))
            {
                return null;
            }
        }
    }

    internal static uint ExtractNegativeTTL(DNSResourceRecord[] authorities)
    {
        foreach (var auth in authorities)
        {
            if (auth.Type == 6 && auth.ParsedRData is SOARecord soa)
            {
                return Math.Min(auth.TTL, soa.Minimum);
            }
        }

        return 0;
    }

    private static bool ValidateResponse(DNSQuery query, DNSResponse response, IPAddress server, string indent)
    {
        if (response.Header.Questions != 1)
        {
            Logger.Warning("{Indent}└─ Invalid question count from {Server}: {Count} (expected 1)",
                indent, server, response.Header.Questions);
            return false;
        }

        if (response.Header.QR != 1)
        {
            Logger.Warning("{Indent}└─ Invalid response from {Server}: QR bit not set (not a response)",
                indent, server);
            return false;
        }

        if (response.Header.Opcode != query.Header.Opcode)
        {
            Logger.Warning(
                "{Indent}└─ Response opcode mismatch from {Server}: expected {Expected}, got {Actual}",
                indent, server, query.Header.Opcode, response.Header.Opcode);
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

        if (response.Question.QClass != query.Question.QClass)
        {
            Logger.Warning(
                "{Indent}└─ Question class mismatch from {Server}: expected {Expected}, got {Actual}",
                indent, server, query.Question.QClass, response.Question.QClass);
            return false;
        }

        return true;
    }

    private static DNSQuery CreateQuery(string qname, ushort qtype)
    {
        var recursionDesired = ForwardingDnsServer is not null || UseDnsOverHttps || UseDnsOverTls;
        return new DNSQuery
        {
            Header = new DNSHeader { RD = recursionDesired ? (byte)1 : (byte)0 },
            Question = new DNSQuestion { QName = qname, QType = qtype }
        };
    }

    internal static string NormalizeQueryName(string qname)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(qname);

        if (!string.Equals(qname, qname.Trim(), StringComparison.Ordinal))
            throw new ArgumentException("DNS names cannot contain leading or trailing whitespace.", nameof(qname));

        var nameWithoutRootDot = qname.EndsWith('.') ? qname[..^1] : qname;
        if (nameWithoutRootDot.Length == 0)
            return string.Empty;

        try
        {
            return new IdnMapping().GetAscii(nameWithoutRootDot).ToLowerInvariant();
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"'{qname}' is not a valid DNS name.", nameof(qname), ex);
        }
    }

    private static bool IsTransientNetworkFailure(Exception exception)
    {
        return exception is SocketException
            or TimeoutException
            or OperationCanceledException
            or IOException
            or InvalidDataException
            or HttpRequestException;
    }

    private static bool CanTrustNegativeResponse(DNSResponse response)
    {
        return response.Header.AA == 1 ||
               ForwardingDnsServer is not null ||
               UseDnsOverHttps ||
               UseDnsOverTls;
    }

    private static bool IsSubdomainOrEqual(string name, string zone)
    {
        if (zone.Length == 0)
            return true;

        return string.Equals(name, zone, StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith($".{zone}", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRootServer(IPAddress server)
    {
        return Array.IndexOf(RootServers, server) >= 0;
    }
}
