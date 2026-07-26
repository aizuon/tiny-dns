using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TinyDNS.Packets;
using TinyDNS.Serialization;

namespace TinyDNS.Tests;

public sealed class TransportTests
{
    [Fact]
    public async Task LengthPrefixedTransportHandlesFragmentedReads()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;

        var serverTask = ServeOneResponse(listener);
        using var client = new TcpClient();
        await client.ConnectAsync(endpoint);

        var query = new DNSQuery
        {
            Header = new DNSHeader { Id = 1234 },
            Question = new DNSQuestion { QName = "example.com" }
        };

        var response = await RecursiveResolver.SendLengthPrefixedQuery(
            query,
            client.GetStream(),
            CancellationToken.None,
            "test");
        await serverTask;

        Assert.Equal(query.Header.Id, response.Header.Id);
        Assert.Equal(query.Question, response.Question);
    }

    private static async Task ServeOneResponse(TcpListener listener)
    {
        using var connection = await listener.AcceptTcpClientAsync();
        var stream = connection.GetStream();

        var lengthPrefix = new byte[2];
        await stream.ReadExactlyAsync(lengthPrefix);
        var requestBytes = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix)];
        await stream.ReadExactlyAsync(requestBytes);

        var requestBuffer = new BinaryBuffer(requestBytes);
        var requestHeader = DNSHeader.Deserialize(requestBuffer);
        var requestQuestion = DNSQuestion.Deserialize(requestBuffer);

        var responseBuffer = new BinaryBuffer();
        new DNSHeader
        {
            Id = requestHeader.Id,
            QR = 1,
            RD = requestHeader.RD,
            RA = 1,
            Questions = 1
        }.SerializeTo(responseBuffer);
        requestQuestion.SerializeTo(responseBuffer);

        BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, (ushort)responseBuffer.Buffer.Count);
        await stream.WriteAsync(lengthPrefix.AsMemory(0, 1));
        await stream.FlushAsync();
        await Task.Delay(5);
        await stream.WriteAsync(lengthPrefix.AsMemory(1, 1));
        await stream.WriteAsync(responseBuffer.Buffer.AsMemory(0, 3));
        await Task.Delay(5);
        await stream.WriteAsync(responseBuffer.Buffer.AsMemory(3));
    }
}
