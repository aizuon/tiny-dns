using System.Net;
using TinyDNS.Packets;
using TinyDNS.Serialization;

namespace TinyDNS.Tests;

public sealed class PacketTests
{
    [Fact]
    public void HeaderFlagsRoundTrip()
    {
        var expected = new DNSHeader
        {
            Id = 65535,
            QR = 1,
            Opcode = 10,
            AA = 1,
            TC = 1,
            RD = 1,
            RA = 1,
            Z = 5,
            RCode = 9,
            Questions = 2,
            AnswerRRs = 3,
            AuthorityRRs = 4,
            AdditionalRRs = 5
        };
        var buffer = new BinaryBuffer();
        expected.SerializeTo(buffer);
        buffer.ReadOffset = 0;

        Assert.Equal(expected, DNSHeader.Deserialize(buffer));
    }

    [Fact]
    public void QuerySerializationIncludesEdnsAndAccurateCounts()
    {
        var query = new DNSQuery
        {
            Header = new DNSHeader { Id = 42, RD = 0 },
            Question = new DNSQuestion
            {
                QName = "example.com",
                QType = (ushort)DNSRecordType.AAAA
            }
        };

        var buffer = query.Serialize();
        buffer.ReadOffset = 0;
        var header = DNSHeader.Deserialize(buffer);
        var question = DNSQuestion.Deserialize(buffer);
        var edns = EDNSOption.Deserialize(buffer);

        Assert.Equal((ushort)42, header.Id);
        Assert.Equal((byte)0, header.RD);
        Assert.Equal((ushort)1, header.Questions);
        Assert.Equal((ushort)1, header.AdditionalRRs);
        Assert.Equal("example.com", question.QName);
        Assert.Equal((ushort)DNSRecordType.AAAA, question.QType);
        Assert.Equal((ushort)1232, edns.UDPSize);
        Assert.Equal(0u, buffer.Remaining);
    }

    [Fact]
    public void ResponseDeserializesCompressedARecord()
    {
        var packet = BuildSingleAnswerPacket(
            DNSRecordType.A,
            [192, 0, 2, 10]);

        var response = DNSResponse.Deserialize(new BinaryBuffer(packet));
        var answer = Assert.Single(response.Answers);

        Assert.Equal("example.com", answer.Name);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), Assert.IsType<IPAddress>(answer.ParsedRData));
        Assert.Null(answer.RData);
    }

    [Fact]
    public void ResponseDeserializesAaaaRecord()
    {
        var address = IPAddress.Parse("2001:db8::1");
        var packet = BuildSingleAnswerPacket(DNSRecordType.AAAA, address.GetAddressBytes());

        var response = DNSResponse.Deserialize(new BinaryBuffer(packet));

        Assert.Equal(address, Assert.IsType<IPAddress>(Assert.Single(response.Answers).ParsedRData));
    }

    [Fact]
    public void TxtRecordConcatenatesAllCharacterStrings()
    {
        var packet = BuildSingleAnswerPacket(
            DNSRecordType.TXT,
            [3, (byte)'f', (byte)'o', (byte)'o', 3, (byte)'b', (byte)'a', (byte)'r']);

        var response = DNSResponse.Deserialize(new BinaryBuffer(packet));

        Assert.Equal("foobar", Assert.IsType<string>(Assert.Single(response.Answers).ParsedRData));
    }

    [Theory]
    [InlineData(DNSRecordType.NS)]
    [InlineData(DNSRecordType.CNAME)]
    [InlineData(DNSRecordType.PTR)]
    public void DomainNameRecordTypesAreParsed(DNSRecordType type)
    {
        var packet = BuildSingleAnswerPacket(type, EncodeDomainName("target.example.com"));

        var response = DNSResponse.Deserialize(new BinaryBuffer(packet));

        Assert.Equal("target.example.com", Assert.IsType<string>(Assert.Single(response.Answers).ParsedRData));
    }

    [Fact]
    public void MxRecordIsParsed()
    {
        var rdata = new BinaryBuffer();
        rdata.Write((ushort)10);
        rdata.WriteDomainName("mail.example.com");

        var packet = BuildSingleAnswerPacket(DNSRecordType.MX, rdata.Buffer.ToArray());
        var mx = Assert.IsType<MXRecord>(
            Assert.Single(DNSResponse.Deserialize(new BinaryBuffer(packet)).Answers).ParsedRData);

        Assert.Equal((ushort)10, mx.Preference);
        Assert.Equal("mail.example.com", mx.Exchange);
    }

    [Fact]
    public void SoaRecordIsParsed()
    {
        var rdata = new BinaryBuffer();
        rdata.WriteDomainName("ns.example.com");
        rdata.WriteDomainName("hostmaster.example.com");
        foreach (var value in new uint[] { 1, 2, 3, 4, 5 })
            rdata.Write(value);

        var packet = BuildSingleAnswerPacket(DNSRecordType.SOA, rdata.Buffer.ToArray());
        var soa = Assert.IsType<SOARecord>(
            Assert.Single(DNSResponse.Deserialize(new BinaryBuffer(packet)).Answers).ParsedRData);

        Assert.Equal("ns.example.com", soa.MName);
        Assert.Equal("hostmaster.example.com", soa.RName);
        Assert.Equal(1u, soa.Serial);
        Assert.Equal(5u, soa.Minimum);
    }

    [Fact]
    public void UnknownRecordDataIsPreserved()
    {
        var packet = BuildSingleAnswerPacket((DNSRecordType)65000, [1, 2, 3]);
        var answer = Assert.Single(DNSResponse.Deserialize(new BinaryBuffer(packet)).Answers);

        Assert.Null(answer.ParsedRData);
        Assert.Equal(new byte[] { 1, 2, 3 }, answer.RData);
    }

    [Fact]
    public void InvalidAddressRdataLengthIsRejected()
    {
        var packet = BuildSingleAnswerPacket(DNSRecordType.A, [192, 0, 2]);

        Assert.Throws<InvalidDataException>(() => DNSResponse.Deserialize(new BinaryBuffer(packet)));
    }

    [Fact]
    public void ExcessiveQuestionCountsAreRejectedBeforeAllocation()
    {
        var buffer = new BinaryBuffer();
        new DNSHeader { QR = 1, Questions = 65 }.SerializeTo(buffer);
        buffer.ReadOffset = 0;

        Assert.Throws<InvalidDataException>(() => DNSResponse.Deserialize(buffer));
    }

    [Fact]
    public void EdnsAggregateLengthOverflowIsRejected()
    {
        var option = new EDNSOption
        {
            Options =
            [
                new EDNSOptionData { Data = new byte[ushort.MaxValue] }
            ]
        };

        Assert.Throws<InvalidOperationException>(() => option.SerializeTo(new BinaryBuffer()));
    }

    private static byte[] BuildSingleAnswerPacket(DNSRecordType type, byte[] rdata)
    {
        var buffer = new BinaryBuffer();
        new DNSHeader
        {
            Id = 7,
            QR = 1,
            RD = 1,
            RA = 1,
            Questions = 1,
            AnswerRRs = 1
        }.SerializeTo(buffer);
        new DNSQuestion
        {
            QName = "example.com",
            QType = (ushort)type
        }.SerializeTo(buffer);

        buffer.WriteBytes([0xC0, 0x0C]);
        buffer.Write((ushort)type);
        buffer.Write((ushort)1);
        buffer.Write(300u);
        buffer.Write((ushort)rdata.Length);
        buffer.WriteBytes(rdata);
        return buffer.Buffer.ToArray();
    }

    private static byte[] EncodeDomainName(string name)
    {
        var buffer = new BinaryBuffer();
        buffer.WriteDomainName(name);
        return buffer.Buffer.ToArray();
    }
}
