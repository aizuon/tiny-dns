using System.Security.Cryptography;
using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSHeader : ISerializable, IDeserializable<DNSHeader>
{
    public ushort Id { get; set; } = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
    public byte QR { get; set; }
    public byte Opcode { get; set; }
    public byte AA { get; set; }
    public byte TC { get; set; }
    public byte RD { get; set; } = 1;
    public byte RA { get; set; }
    public byte Z { get; set; }
    public byte RCode { get; set; }
    public ushort Questions { get; set; } = 1;
    public ushort AnswerRRs { get; set; }
    public ushort AuthorityRRs { get; set; }
    public ushort AdditionalRRs { get; set; }

    public static DNSHeader Deserialize(BinaryBuffer buffer)
    {
        var header = new DNSHeader();

        header.Id = buffer.Read<ushort>();

        ushort flags = buffer.Read<ushort>();
        header.QR = (byte)((flags >> 15) & 0x1);
        header.Opcode = (byte)((flags >> 11) & 0xF);
        header.AA = (byte)((flags >> 10) & 0x1);
        header.TC = (byte)((flags >> 9) & 0x1);
        header.RD = (byte)((flags >> 8) & 0x1);
        header.RA = (byte)((flags >> 7) & 0x1);
        header.Z = (byte)((flags >> 4) & 0x7);
        header.RCode = (byte)(flags & 0xF);

        header.Questions = buffer.Read<ushort>();
        header.AnswerRRs = buffer.Read<ushort>();
        header.AuthorityRRs = buffer.Read<ushort>();
        header.AdditionalRRs = buffer.Read<ushort>();

        return header;
    }

    public void SerializeTo(BinaryBuffer buffer)
    {
        buffer.Write(Id);

        ushort flags = (ushort)(
            ((QR & 0x1) << 15) |
            ((Opcode & 0xF) << 11) |
            ((AA & 0x1) << 10) |
            ((TC & 0x1) << 9) |
            ((RD & 0x1) << 8) |
            ((RA & 0x1) << 7) |
            ((Z & 0x7) << 4) |
            (RCode & 0xF));
        buffer.Write(flags);

        buffer.Write(Questions);
        buffer.Write(AnswerRRs);
        buffer.Write(AuthorityRRs);
        buffer.Write(AdditionalRRs);
    }
}
