using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public interface ISerializable
{
    public void SerializeTo(BinaryBuffer buffer);
}
