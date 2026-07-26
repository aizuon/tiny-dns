using System.Diagnostics;
using System.Net;
using TinyDNS;

Log.Init();

var queryName = "www.google.com";
DNSRecordType? queryType = null;
IPAddress? reverseAddress = null;
for (var index = 0; index < args.Length; index++)
{
    switch (args[index])
    {
        case "--server" when index + 1 < args.Length:
            if (!IPAddress.TryParse(args[++index], out var forwardingServer))
                throw new ArgumentException($"Invalid forwarding server address: {args[index]}");
            RecursiveResolver.ForwardingDnsServer = forwardingServer;
            break;

        case "--doh" when index + 1 < args.Length:
            RecursiveResolver.UseDnsOverHttps = true;
            RecursiveResolver.DnsOverHttpsUrl = args[++index];
            break;

        case "--dot" when index + 1 < args.Length:
            RecursiveResolver.UseDnsOverTls = true;
            RecursiveResolver.DnsOverTlsHostName = args[++index];
            break;

        case "--type" when index + 1 < args.Length:
            if (!Enum.TryParse<DNSRecordType>(args[++index], true, out var parsedType) ||
                !Enum.IsDefined(parsedType))
            {
                throw new ArgumentException($"Unsupported DNS record type: {args[index]}");
            }
            queryType = parsedType;
            break;

        case "--reverse" when index + 1 < args.Length:
            if (!IPAddress.TryParse(args[++index], out reverseAddress))
                throw new ArgumentException($"Invalid reverse-lookup address: {args[index]}");
            break;

        case "--help":
            Console.WriteLine(
                """
                Usage:
                  tiny-sandbox [name] [--type TYPE] [--server IP] [--doh URL] [--dot TLS_HOSTNAME]
                  tiny-sandbox --reverse IP [--server IP] [--doh URL] [--dot TLS_HOSTNAME]
                """);
            return;

        case var argument when argument.StartsWith("--", StringComparison.Ordinal):
            throw new ArgumentException($"Unknown or incomplete option: {argument}");

        default:
            queryName = args[index];
            break;
    }
}

using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var stopwatch = Stopwatch.StartNew();

if (reverseAddress is not null)
{
    var hostname = await RecursiveResolver.ReverseLookup(reverseAddress, cancellation.Token);
    Console.WriteLine(hostname is null
        ? $"No PTR record found for {reverseAddress}."
        : $"{reverseAddress} resolves to {hostname}.");
}
else if (queryType is not null)
{
    var records = await RecursiveResolver.Query(queryName, queryType.Value, cancellation.Token);
    foreach (var record in records)
    {
        var data = record.ParsedRData?.ToString() ??
                   (record.RData is { Length: > 0 } ? Convert.ToHexString(record.RData) : "<empty>");
        Console.WriteLine($"{record.Name} {record.TTL} IN {(DNSRecordType)record.Type} {data}");
    }

    if (records.Length == 0)
        Console.WriteLine($"No {queryType} records found for {queryName}.");
}
else
{
    var result = await RecursiveResolver.Resolve(queryName, cancellation.Token);
    Console.WriteLine(result is null
        ? $"No A record found for {queryName}."
        : $"{queryName} resolved to {result}.");
}

stopwatch.Stop();
Console.WriteLine($"Elapsed: {stopwatch.ElapsedMilliseconds:N0} ms");
