namespace TinyDNS;

public sealed class NegativeCacheEntry
{
    public static readonly NegativeCacheEntry Instance = new();

    private NegativeCacheEntry()
    {
    }
}
