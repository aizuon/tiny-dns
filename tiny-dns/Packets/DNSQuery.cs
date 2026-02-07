using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSQuery : ISerializable
{
    public DNSHeader Header { get; set; }
    public DNSQuestion Question { get; set; }
    public EDNSOption EDNSOption { get; set; } = new EDNSOption();

    public BinaryBuffer Serialize()
    {
        var buffer = new BinaryBuffer();
        SerializeTo(buffer);
        return buffer;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        if (EDNSOption != null)
            Header.AdditionalRRs = 1;
        Header.SerializeTo(buffer);
        Question.SerializeTo(buffer);
        EDNSOption?.SerializeTo(buffer);
    }
}
