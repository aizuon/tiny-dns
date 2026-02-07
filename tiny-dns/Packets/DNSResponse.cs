using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSResponse : IDeserializable<DNSResponse>
{
    public DNSHeader Header { get; set; }
    public DNSQuestion Question { get; set; }
    public DNSResourceRecord[] Answers { get; set; }
    public DNSResourceRecord[] Authorities { get; set; }
    public DNSResourceRecord[] Additionals { get; set; }

    public static DNSResponse Deserialize(BinaryBuffer buffer)
    {
        var response = new DNSResponse();

        response.Header = DNSHeader.Deserialize(buffer);
        response.Question = DNSQuestion.Deserialize(buffer);

        var header = response.Header;
        response.Answers = new DNSResourceRecord[header.AnswerRRs];
        for (int i = 0; i < header.AnswerRRs; i++)
            response.Answers[i] = DNSResourceRecord.Deserialize(buffer);

        response.Authorities = new DNSResourceRecord[header.AuthorityRRs];
        for (int i = 0; i < header.AuthorityRRs; i++)
            response.Authorities[i] = DNSResourceRecord.Deserialize(buffer);

        response.Additionals = new DNSResourceRecord[header.AdditionalRRs];
        for (int i = 0; i < header.AdditionalRRs; i++)
            response.Additionals[i] = DNSResourceRecord.Deserialize(buffer);

        return response;
    }
}
