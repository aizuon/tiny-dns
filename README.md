# tiny-dns

A minimal recursive DNS resolver written in C#. Resolves domain names by walking the DNS hierarchy from the root servers, with in-memory caching and structured logging.

## Features

- **Recursive resolution** — starts from root server `198.41.0.4` and follows NS/glue records down to the authoritative answer
- **EDNS(0) support** — sends OPT records with configurable options
- **In-memory caching** — caches resolved records with TTL-based expiration via `Microsoft.Extensions.Caching.Memory`
- **Structured logging** — uses Serilog with async console and file sinks
- **Zero-copy serialization** — `BinaryBuffer` backed by `Span<T>`, `BinaryPrimitives`, and `stackalloc` for minimal allocations on the hot path

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

var result = await RecursiveResolver.Resolve("www.google.com");
Console.WriteLine(result);   // resolved IP address
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

- [ ] **Additional record types** — AAAA (IPv6), CNAME, MX, TXT, SOA, PTR
- [ ] **DNSSEC validation** — verify authenticated responses with RRSIG/DNSKEY records
- [ ] **DNS-over-HTTPS (DoH)** — secure DNS queries over HTTPS
- [ ] **DNS-over-TLS (DoT)** — encrypted DNS transport layer
- [ ] **Parallel queries** — query multiple nameservers simultaneously for faster resolution
- [ ] **Negative caching** — cache NXDOMAIN and NODATA responses
- [ ] **Response validation** — verify response consistency, detect spoofing attempts
- [ ] **Rate limiting** — per-nameserver and global query rate limits
- [ ] **Query tracing** — detailed debug mode showing full resolution path

## License

[MIT](LICENSE) — Copyright (c) 2026 Dorq
