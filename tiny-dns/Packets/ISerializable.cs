using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public interface ISerializable
{
    void SerializeTo(BinaryBuffer buffer);
}
