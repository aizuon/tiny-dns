# tiny-dns

A minimal recursive DNS resolver written in C#. Resolves domain names by walking the DNS hierarchy from the root servers, with in-memory caching and structured logging.

## Features

- **Recursive resolution** — starts from all 13 root servers (a-m.root-servers.net) with round-robin load balancing and automatic fallback
- **DNS forwarding** — optionally forward queries to upstream recursive DNS servers (1.1.1.1, 8.8.8.8, etc.) instead of starting from root servers
- **DNS-over-TLS (DoT)** — optional encrypted DNS queries over TLS on port 853 for enhanced privacy and security
- **DNS-over-HTTPS (DoH)** — secure DNS queries over HTTPS with support for major providers (Cloudflare, Google, Quad9)
- **Parallel nameserver queries** — queries multiple authoritative nameservers simultaneously, using whichever responds first for optimal performance
- **EDNS(0) support** — sends OPT records with configurable options
- **In-memory caching** — caches resolved records with TTL-based expiration via `Microsoft.Extensions.Caching.Memory`
- **Structured logging** — uses Serilog with async console and file sinks
- **Zero-copy serialization** — `BinaryBuffer` backed by `Span<T>`, `BinaryPrimitives`, and `stackalloc` for minimal allocations on the hot path
- **Root server resilience** — automatically retries with different root servers on timeout or connection failure

## Requirements

- [.NET 10.0](https://dotnet.microsoft.com/) or later

## Project Structure

```
tiny-dns/           # Core library
  Packets/          # DNS wire-format types (Header, Question, ResourceRecord, …)
  Serialization/    # BinaryBuffer, Mem (endianness utilities)
  RecursiveResolver.cs
  Log.cs

tiny-sandbox/       # Demo console app
  Program.cs
```

## Usage

```csharp
using TinyDNS;

Log.Init();

// Resolve A record (IPv4 address)
var result = await RecursiveResolver.Resolve("www.google.com");
Console.WriteLine($"IP: {result}");

// Query MX records (mail servers)
var mxRecords = await RecursiveResolver.Query("gmail.com", DNSRecordType.MX);
foreach (var record in mxRecords)
{
    if (record.ParsedRData is MXRecord mx)
        Console.WriteLine($"MX: {mx.Preference} {mx.Exchange}");
}

// Query TXT records
var txtRecords = await RecursiveResolver.Query("google.com", DNSRecordType.TXT);
foreach (var record in txtRecords)
{
    if (record.ParsedRData is string txt)
        Console.WriteLine($"TXT: {txt}");
}

// Reverse DNS lookup (PTR record)
var hostname = await RecursiveResolver.ReverseLookup(IPAddress.Parse("8.8.8.8"));
Console.WriteLine($"Hostname: {hostname}");

// Enable DNS-over-TLS for encrypted queries
RecursiveResolver.UseDnsOverTls = true;
var secureResult = await RecursiveResolver.Resolve("www.cloudflare.com");
Console.WriteLine($"IP (via DoT): {secureResult}");

// Enable DNS-over-HTTPS for encrypted queries via HTTPS
RecursiveResolver.UseDnsOverHttps = true;
RecursiveResolver.DnsOverHttpsUrl = "https://1.1.1.1/dns-query";
var dohResult = await RecursiveResolver.Resolve("www.example.com");
Console.WriteLine($"IP (via DoH): {dohResult}");

// Forward queries to a recursive DNS server (like your system DNS)
RecursiveResolver.ForwardingDnsServer = IPAddress.Parse("1.1.1.1");
var forwardResult = await RecursiveResolver.Resolve("www.github.com");
Console.WriteLine($"IP (forwarded): {forwardResult}");

// Combine forwarding with DNS-over-TLS for encrypted forwarding
RecursiveResolver.ForwardingDnsServer = IPAddress.Parse("1.1.1.1");
RecursiveResolver.UseDnsOverTls = true;
var secureForward = await RecursiveResolver.Resolve("www.example.com");
Console.WriteLine($"IP (forwarded via DoT): {secureForward}");

// Testing/Development ONLY - accepts self-signed certs (INSECURE!)
RecursiveResolver.AllowInvalidCertificates = true;  // ⚠️ NEVER USE IN PRODUCTION

```

Run the sandbox project:

```bash
dotnet run --project tiny-sandbox
```

## Dependencies

| Package                             | Version |
| ----------------------------------- | ------- |
| Serilog                             | 4.3.0   |
| Serilog.Sinks.Async                 | 2.1.0   |
| Serilog.Sinks.Console               | 6.1.1   |
| Serilog.Sinks.File                  | 7.0.0   |
| Microsoft.Extensions.Caching.Memory | 10.0.2  |

## Planned Features

- [ ] **DNSSEC validation** — verify authenticated responses with RRSIG/DNSKEY records

## License

[MIT](LICENSE) — Copyright (c) 2026 Dorq
