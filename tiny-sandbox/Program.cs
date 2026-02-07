using System.Diagnostics;
using TinyDNS;

namespace TinySandbox;

internal class Program
{
    private static async Task Main()
    {
        Log.Init();

        var sw = Stopwatch.StartNew();
        var result = await RecursiveResolver.Resolve("www.google.com");
        sw.Stop();
        Console.WriteLine(result);
        Console.WriteLine(sw.ElapsedMilliseconds);
    }
}
