# tiny-dns

A compact recursive DNS resolver written in C#. It can walk the DNS hierarchy from the root, forward to a recursive upstream, or use an encrypted DNS transport.

## Features

- Iterative resolution starting from all 13 IPv4 root-server addresses, with rotation and fallback
- Parallel authoritative-server queries with bounded fan-out
- UDP with automatic TCP retry when a response is truncated
- Optional forwarding to a recursive DNS server
- DNS-over-TLS (DoT) forwarding with certificate and hostname validation
- DNS-over-HTTPS (DoH) using `application/dns-message`
- EDNS(0) with a fragmentation-conscious 1,232-byte UDP payload size
- Positive A-result and negative TTL-based in-memory caching
- A, AAAA, NS, CNAME, SOA, PTR, MX, and multi-string TXT parsing
- IPv4 and IPv6 reverse lookups
- IDNA normalization for internationalized domain names
- Bounds-checked, span-based DNS wire serialization and compression decoding
- Structured Serilog console and rolling-file output
- Per-server and global sliding-window rate limits

The resolver validates transaction IDs, question names/types/classes, response opcodes, packet bounds, RDATA lengths, and compression pointers before trusting a response. DNSSEC validation is not implemented yet.

## Requirements

- [.NET 10.0](https://dotnet.microsoft.com/) or later

## Usage

```csharp
using System.Net;
using TinyDNS;
using TinyDNS.Packets;

Log.Init();

// Iterative A lookup from the DNS root.
IPAddress? address = await RecursiveResolver.Resolve("www.example.com");

// Query another supported record type.
DNSResourceRecord[] mxRecords =
    await RecursiveResolver.Query("example.com", DNSRecordType.MX);

foreach (var record in mxRecords)
{
    if (record.ParsedRData is MXRecord mx)
        Console.WriteLine($"{mx.Preference} {mx.Exchange}");
}

// IPv4 and IPv6 PTR lookups are supported.
string? hostname =
    await RecursiveResolver.ReverseLookup(IPAddress.Parse("2001:4860:4860::8888"));
```

Internationalized names are converted to IDNA automatically. Public resolution methods accept a `CancellationToken`, and `Resolve`/`ReverseLookup` return `null` when no matching record is found.

### Forwarding

```csharp
RecursiveResolver.ForwardingDnsServer = IPAddress.Parse("1.1.1.1");
IPAddress? address = await RecursiveResolver.Resolve("www.example.com");
```

### DNS-over-TLS

DoT is an encrypted connection to a recursive upstream, so a forwarding address is required. Set the TLS hostname to match the provider certificate:

```csharp
RecursiveResolver.ForwardingDnsServer = IPAddress.Parse("1.1.1.1");
RecursiveResolver.UseDnsOverTls = true;
RecursiveResolver.DnsOverTlsHostName = "cloudflare-dns.com";

IPAddress? address = await RecursiveResolver.Resolve("www.example.com");
```

`AllowInvalidCertificates` exists only for controlled development environments. Enabling it disables a critical transport security check and should never be used in production.

### DNS-over-HTTPS

```csharp
RecursiveResolver.UseDnsOverHttps = true;
RecursiveResolver.DnsOverHttpsUrl = "https://cloudflare-dns.com/dns-query";

IPAddress? address = await RecursiveResolver.Resolve("www.example.com");
```

If both encrypted transports are enabled, DoH takes precedence. Configure the static resolver properties before starting concurrent requests.

## Sandbox

```bash
# Iterative lookup
dotnet run --project tiny-sandbox -- example.com

# UDP forwarding
dotnet run --project tiny-sandbox -- example.com --server 1.1.1.1

# Record query
dotnet run --project tiny-sandbox -- example.com --type AAAA --server 1.1.1.1

# Reverse lookup
dotnet run --project tiny-sandbox -- --reverse 8.8.8.8 --server 1.1.1.1

# DoH
dotnet run --project tiny-sandbox -- example.com \
  --doh https://cloudflare-dns.com/dns-query

# DoT
dotnet run --project tiny-sandbox -- example.com \
  --server 1.1.1.1 --dot cloudflare-dns.com
```

Run `dotnet run --project tiny-sandbox -- --help` for the option summary.

## Development

```bash
dotnet restore tiny-dns.sln
dotnet build tiny-dns.sln -c Release --no-restore
dotnet test tiny-dns.sln -c Release --no-build
dotnet format tiny-dns.sln --verify-no-changes --no-restore
```

The test suite covers wire-format round trips, malformed packets, compression pointers, A/AAAA/TXT parsing, EDNS limits, rate-limit concurrency, cancellation, IDNA, negative caching rules, and parallel nameserver selection.

## Project structure

```text
tiny-dns/         Core library
  Packets/        DNS wire-format types
  Serialization/  Bounds-checked binary buffer and endian utilities
tiny-dns.Tests/   Unit and concurrency regression tests
tiny-sandbox/     Command-line demonstration app
```

## Runtime dependencies

| Package                             | Version |
| ----------------------------------- | ------- |
| Microsoft.Extensions.Caching.Memory | 10.0.2  |
| Serilog                             | 4.3.0   |
| Serilog.Sinks.Async                 | 2.1.0   |
| Serilog.Sinks.Console               | 6.1.1   |
| Serilog.Sinks.File                  | 7.0.0   |

## Planned features

- DNSSEC validation with RRSIG and DNSKEY verification

## License

[MIT](LICENSE) — Copyright (c) 2026 Dorq
