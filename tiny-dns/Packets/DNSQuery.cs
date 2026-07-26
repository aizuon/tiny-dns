using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSQuery : ISerializable
{
    public DNSHeader Header { get; set; } = new();
    public DNSQuestion Question { get; set; } = new();
    public EDNSOption? EDNSOption { get; set; } = new();

    public BinaryBuffer Serialize()
    {
        var buffer = new BinaryBuffer();
        SerializeTo(buffer);
        return buffer;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        Header.Questions = 1;
        Header.AdditionalRRs = EDNSOption is null ? (ushort)0 : (ushort)1;
        Header.SerializeTo(buffer);
        Question.SerializeTo(buffer);
        EDNSOption?.SerializeTo(buffer);
    }
}
