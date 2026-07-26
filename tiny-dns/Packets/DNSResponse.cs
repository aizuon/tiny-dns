using TinyDNS.Serialization;

namespace TinyDNS.Packets;

public record DNSResponse : IDeserializable<DNSResponse>
{
    public DNSHeader Header { get; set; } = new();
    public DNSQuestion Question { get; set; } = new();
    public DNSResourceRecord[] Answers { get; set; } = [];
    public DNSResourceRecord[] Authorities { get; set; } = [];
    public DNSResourceRecord[] Additionals { get; set; } = [];

    private const int MaxQuestionCount = 64;
    private const int MaxRRCount = 4096;

    public static DNSResponse Deserialize(BinaryBuffer buffer)
    {
        var response = new DNSResponse();

        response.Header = DNSHeader.Deserialize(buffer);
        var header = response.Header;

        if (header.Questions > MaxQuestionCount)
            throw new InvalidDataException($"DNS response has excessive question count: {header.Questions}");
        if (header.AnswerRRs > MaxRRCount || header.AuthorityRRs > MaxRRCount || header.AdditionalRRs > MaxRRCount)
            throw new InvalidDataException(
                $"DNS response has excessive RR counts: {header.AnswerRRs}/{header.AuthorityRRs}/{header.AdditionalRRs}");

        for (var i = 0; i < header.Questions; i++)
        {
            var question = DNSQuestion.Deserialize(buffer);
            if (i == 0)
                response.Question = question;
        }

        response.Answers = new DNSResourceRecord[header.AnswerRRs];
        for (var i = 0; i < header.AnswerRRs; i++)
            response.Answers[i] = DNSResourceRecord.Deserialize(buffer);

        response.Authorities = new DNSResourceRecord[header.AuthorityRRs];
        for (var i = 0; i < header.AuthorityRRs; i++)
            response.Authorities[i] = DNSResourceRecord.Deserialize(buffer);

        response.Additionals = new DNSResourceRecord[header.AdditionalRRs];
        for (var i = 0; i < header.AdditionalRRs; i++)
            response.Additionals[i] = DNSResourceRecord.Deserialize(buffer);

        return response;
    }
}
