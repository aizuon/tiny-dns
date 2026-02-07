using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record EDNSOption : ISerializable, IDeserializable<EDNSOption>
{
    public ushort UDPSize { get; set; } = 4096;
    public byte ExtendedRCode { get; set; }
    public byte Version { get; set; }
    public ushort Flags { get; set; }
    public List<EDNSOptionData> Options { get; set; } = [];

    public static EDNSOption Deserialize(BinaryBuffer buffer)
    {
        var ednsOption = new EDNSOption();

        byte name = buffer.Read<byte>();
        if (name != 0)
            return null;

        ushort type = buffer.Read<ushort>();
        if (type != 41)
            return null;

        ednsOption.UDPSize = buffer.Read<ushort>();

        uint ttl = buffer.Read<uint>();

        ednsOption.ExtendedRCode = (byte)((ttl >> 24) & 0xFF);
        ednsOption.Version = (byte)((ttl >> 16) & 0xFF);
        ednsOption.Flags = (ushort)(ttl & 0xFFFF);

        ushort rdLength = buffer.Read<ushort>();

        if (rdLength > 0)
        {
            uint endPosition = buffer.ReadOffset + rdLength;
            while (buffer.ReadOffset < endPosition)
            {
                var option = EDNSOptionData.Deserialize(buffer);
                if (option == null)
                    return null;
                ednsOption.Options.Add(option);
            }
        }

        return ednsOption;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        buffer.Write((byte)0);

        buffer.Write((ushort)41);

        buffer.Write(UDPSize);

        uint ttl = (uint)((ExtendedRCode << 24) | (Version << 16) | Flags);
        buffer.Write(ttl);

        ushort rdLength = 0;
        foreach (var option in Options)
            rdLength += (ushort)(4 + option.Data.Length);
        buffer.Write(rdLength);

        foreach (var option in Options)
            option.SerializeTo(buffer);
    }
}
