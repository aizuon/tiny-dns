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
}
