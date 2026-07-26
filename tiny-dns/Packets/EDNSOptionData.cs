using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record EDNSOptionData : ISerializable, IDeserializable<EDNSOptionData>
{
    public ushort Code { get; set; }
    public byte[] Data { get; set; } = [];

    public static EDNSOptionData Deserialize(BinaryBuffer buffer)
    {
        var optionData = new EDNSOptionData();
        optionData.Code = buffer.Read<ushort>();
        ushort dataLength = buffer.Read<ushort>();
        optionData.Data = buffer.ReadBytes(dataLength);
        return optionData;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        if (Data.Length > ushort.MaxValue)
            throw new InvalidOperationException("EDNS option data cannot exceed 65,535 bytes.");

        buffer.Write(Code);
        buffer.Write((ushort)Data.Length);
        buffer.WriteBytes(Data);
    }
}
