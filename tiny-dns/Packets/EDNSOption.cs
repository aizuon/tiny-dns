using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record EDNSOption : ISerializable, IDeserializable<EDNSOption>
{
    public ushort UDPSize { get; set; } = 1232;
    public byte ExtendedRCode { get; set; }
    public byte Version { get; set; }
    public ushort Flags { get; set; }
    public List<EDNSOptionData> Options { get; set; } = [];

    public static EDNSOption Deserialize(BinaryBuffer buffer)
    {
        var ednsOption = new EDNSOption();

        byte name = buffer.Read<byte>();
        if (name != 0)
            throw new InvalidDataException("An EDNS OPT record must use the root owner name.");

        ushort type = buffer.Read<ushort>();
        if (type != 41)
            throw new InvalidDataException($"Expected an EDNS OPT record (type 41), got type {type}.");

        ednsOption.UDPSize = buffer.Read<ushort>();

        uint ttl = buffer.Read<uint>();

        ednsOption.ExtendedRCode = (byte)((ttl >> 24) & 0xFF);
        ednsOption.Version = (byte)((ttl >> 16) & 0xFF);
        ednsOption.Flags = (ushort)(ttl & 0xFFFF);

        ushort rdLength = buffer.Read<ushort>();
        if (rdLength > buffer.Remaining)
            throw new InvalidDataException("EDNS option data exceeds the packet boundary.");

        uint endPosition = buffer.ReadOffset + rdLength;
        while (buffer.ReadOffset < endPosition)
        {
            if (endPosition - buffer.ReadOffset < 4)
                throw new InvalidDataException("EDNS option header is truncated.");

            ednsOption.Options.Add(EDNSOptionData.Deserialize(buffer));
        }

        if (buffer.ReadOffset != endPosition)
            throw new InvalidDataException("EDNS option length does not match its encoded data.");

        return ednsOption;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        buffer.Write((byte)0);

        buffer.Write((ushort)41);

        buffer.Write(UDPSize);

        uint ttl = (uint)((ExtendedRCode << 24) | (Version << 16) | Flags);
        buffer.Write(ttl);

        var rdLength = 0;
        foreach (var option in Options)
        {
            if (option.Data.Length > ushort.MaxValue)
                throw new InvalidOperationException("EDNS option data cannot exceed 65,535 bytes.");

            rdLength = checked(rdLength + 4 + option.Data.Length);
        }

        if (rdLength > ushort.MaxValue)
            throw new InvalidOperationException("Combined EDNS option data cannot exceed 65,535 bytes.");

        buffer.Write((ushort)rdLength);

        foreach (var option in Options)
            option.SerializeTo(buffer);
    }
}
