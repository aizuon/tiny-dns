using TinyDNS.Serialization;

namespace TinyDNS.Tests;

public sealed class BinaryBufferTests
{
    [Fact]
    public void NumericValuesRoundTripInNetworkByteOrder()
    {
        var buffer = new BinaryBuffer();
        buffer.Write((ushort)0x1234);
        buffer.Write(0x89ABCDEFu);

        Assert.Equal(new byte[] { 0x12, 0x34, 0x89, 0xAB, 0xCD, 0xEF }, buffer.Buffer.ToArray());

        buffer.ReadOffset = 0;
        Assert.Equal((ushort)0x1234, buffer.Read<ushort>());
        Assert.Equal(0x89ABCDEFu, buffer.Read<uint>());
        Assert.Equal(0u, buffer.Remaining);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(".", "")]
    [InlineData("www.example.com", "www.example.com")]
    [InlineData("www.example.com.", "www.example.com")]
    public void DomainNamesRoundTrip(string input, string expected)
    {
        var buffer = new BinaryBuffer();
        buffer.WriteDomainName(input);
        buffer.ReadOffset = 0;

        Assert.Equal(expected, buffer.ReadDomainName());
        Assert.Equal(0u, buffer.Remaining);
    }

    [Fact]
    public void CompressionPointersAreDecodedAndAdvancePastThePointer()
    {
        var buffer = new BinaryBuffer();
        buffer.WriteDomainName("www.example.com");
        var pointerPosition = buffer.Length;
        buffer.WriteBytes([0xC0, 0x04]);

        buffer.ReadOffset = pointerPosition;

        Assert.Equal("example.com", buffer.ReadDomainName());
        Assert.Equal(pointerPosition + 2, buffer.ReadOffset);
    }

    [Fact]
    public void CompressionPointerLoopsAreRejected()
    {
        var buffer = new BinaryBuffer([0xC0, 0x00]);

        Assert.Throws<InvalidDataException>(buffer.ReadDomainName);
    }

    [Fact]
    public void ReadsCannotCrossTheLogicalBufferLength()
    {
        var buffer = new BinaryBuffer();
        buffer.Write((byte)1);
        buffer.ReadOffset = 0;

        Assert.Throws<InvalidDataException>(() => buffer.Read<ushort>());
    }

    [Theory]
    [InlineData("example..com")]
    [InlineData(".example.com")]
    [InlineData("münich.example")]
    public void InvalidWireNamesAreRejected(string name)
    {
        var buffer = new BinaryBuffer();

        Assert.Throws<ArgumentException>(() => buffer.WriteDomainName(name));
    }
}
