using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public interface IDeserializable<out T>
{
    static abstract T Deserialize(BinaryBuffer buffer);
}
