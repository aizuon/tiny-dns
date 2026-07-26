using System.Net;
using System.Text;
using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSResourceRecord : IDeserializable<DNSResourceRecord>
{
    public string Name { get; set; } = string.Empty;
    public ushort Type { get; set; }
    public ushort Class { get; set; }
    public uint TTL { get; set; }
    public byte[]? RData { get; set; }
    public object? ParsedRData { get; set; }

    public static DNSResourceRecord Deserialize(BinaryBuffer buffer)
    {
        var record = new DNSResourceRecord
        {
            Name = buffer.ReadDomainName(),
            Type = buffer.Read<ushort>(),
            Class = buffer.Read<ushort>(),
            TTL = buffer.Read<uint>()
        };

        var rdLength = buffer.Read<ushort>();
        if (rdLength > buffer.Remaining)
            throw new InvalidDataException("Resource-record data exceeds the DNS packet boundary.");

        var rdStart = buffer.ReadOffset;
        var rdEnd = rdStart + rdLength;
        record.ParsedRData = record.ParseRData(buffer, rdEnd, rdLength);

        if (record.ParsedRData is null)
        {
            buffer.ReadOffset = rdStart;
            record.RData = buffer.ReadBytes(rdLength);
        }
        else if (buffer.ReadOffset != rdEnd)
        {
            throw new InvalidDataException(
                $"Resource record type {record.Type} did not consume its declared RDATA length.");
        }

        return record;
    }

    private object? ParseRData(BinaryBuffer buffer, uint rdEnd, ushort rdLength)
    {
        return (DNSRecordType)Type switch
        {
            DNSRecordType.A => ParseAddressRecord(buffer, rdLength, 4),
            DNSRecordType.NS => buffer.ReadDomainName(),
            DNSRecordType.CNAME => buffer.ReadDomainName(),
            DNSRecordType.SOA => ParseSOARecord(buffer),
            DNSRecordType.PTR => buffer.ReadDomainName(),
            DNSRecordType.MX => ParseMXRecord(buffer),
            DNSRecordType.TXT => ParseTXTRecord(buffer, rdEnd),
            DNSRecordType.AAAA => ParseAddressRecord(buffer, rdLength, 16),
            _ => null
        };
    }

    private static IPAddress ParseAddressRecord(BinaryBuffer buffer, ushort rdLength, ushort expectedLength)
    {
        if (rdLength != expectedLength)
        {
            throw new InvalidDataException(
                $"Address record has an invalid RDATA length of {rdLength}; expected {expectedLength}.");
        }

        return new IPAddress(buffer.ReadBytesSpan(expectedLength));
    }

    private static SOARecord ParseSOARecord(BinaryBuffer buffer)
    {
        return new SOARecord
        {
            MName = buffer.ReadDomainName(),
            RName = buffer.ReadDomainName(),
            Serial = buffer.Read<uint>(),
            Refresh = buffer.Read<uint>(),
            Retry = buffer.Read<uint>(),
            Expire = buffer.Read<uint>(),
            Minimum = buffer.Read<uint>()
        };
    }

    private static MXRecord ParseMXRecord(BinaryBuffer buffer)
    {
        return new MXRecord
        {
            Preference = buffer.Read<ushort>(),
            Exchange = buffer.ReadDomainName()
        };
    }

    private static string ParseTXTRecord(BinaryBuffer buffer, uint rdEnd)
    {
        var result = new StringBuilder();

        while (buffer.ReadOffset < rdEnd)
        {
            var stringLength = buffer.Read<byte>();
            if (stringLength > rdEnd - buffer.ReadOffset)
                throw new InvalidDataException("TXT character-string exceeds its RDATA boundary.");

            result.Append(Encoding.UTF8.GetString(buffer.ReadBytesSpan(stringLength)));
        }

        return result.ToString();
    }
}

public record SOARecord
{
    public string MName { get; init; } = string.Empty;
    public string RName { get; init; } = string.Empty;
    public uint Serial { get; init; }
    public uint Refresh { get; init; }
    public uint Retry { get; init; }
    public uint Expire { get; init; }
    public uint Minimum { get; init; }
}

public record MXRecord
{
    public ushort Preference { get; init; }
    public string Exchange { get; init; } = string.Empty;
}
