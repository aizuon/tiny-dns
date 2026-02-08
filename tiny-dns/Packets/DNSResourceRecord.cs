using System.Net;
using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSResourceRecord : IDeserializable<DNSResourceRecord>
{
    public string Name { get; set; }
    public ushort Type { get; set; }
    public ushort Class { get; set; }
    public uint TTL { get; set; }
    public byte[] RData { get; set; }
    public object ParsedRData { get; set; }

    public static DNSResourceRecord Deserialize(BinaryBuffer buffer)
    {
        var record = new DNSResourceRecord();

        record.Name = buffer.ReadDomainName();
        record.Type = buffer.Read<ushort>();
        record.Class = buffer.Read<ushort>();
        record.TTL = buffer.Read<uint>();

        ushort rdLength = buffer.Read<ushort>();
        uint rdStart = buffer.ReadOffset;
        record.ParseRData(buffer);
        if (record.ParsedRData == null)
        {
            buffer.ReadOffset = rdStart;
            record.RData = buffer.ReadBytes(rdLength);
        }
        else
        {
            buffer.ReadOffset = rdStart + rdLength;
        }

        return record;
    }

    private void ParseRData(BinaryBuffer buffer)
    {
        switch (Type)
        {
            case 1:
                ParsedRData = ParseARecord(buffer);
                break;
            case 2:
                ParsedRData = ParseNSRecord(buffer);
                break;
            case 5:
                ParsedRData = ParseCNAMERecord(buffer);
                break;
            case 6:
                ParsedRData = ParseSOARecord(buffer);
                break;
            case 12:
                ParsedRData = ParsePTRRecord(buffer);
                break;
            case 15:
                ParsedRData = ParseMXRecord(buffer);
                break;
            case 16:
                ParsedRData = ParseTXTRecord(buffer);
                break;
        }
    }

    private static IPAddress ParseARecord(BinaryBuffer buffer)
    {
        var octets = buffer.ReadBytesSpan(4);
        return new IPAddress(octets);
    }

    private static string ParseNSRecord(BinaryBuffer buffer)
    {
        return buffer.ReadDomainName();
    }

    private static string ParseCNAMERecord(BinaryBuffer buffer)
    {
        return buffer.ReadDomainName();
    }

    private static string ParsePTRRecord(BinaryBuffer buffer)
    {
        return buffer.ReadDomainName();
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

    private static string ParseTXTRecord(BinaryBuffer buffer)
    {
        byte length = buffer.Read<byte>();
        return System.Text.Encoding.UTF8.GetString(buffer.ReadBytesSpan(length));
    }
}

public record SOARecord
{
    public string MName { get; init; }
    public string RName { get; init; }
    public uint Serial { get; init; }
    public uint Refresh { get; init; }
    public uint Retry { get; init; }
    public uint Expire { get; init; }
    public uint Minimum { get; init; }
}

public record MXRecord
{
    public ushort Preference { get; init; }
    public string Exchange { get; init; }
}
