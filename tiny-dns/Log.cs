using System.Collections.Concurrent;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace TinyDNS;

public static class Log
{
    public static void Init()
    {
        Serilog.Log.Logger = new LoggerConfiguration()
            .WriteTo.Async(log =>
                log.File(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "log/log_.log"),
                    outputTemplate:
                    "[{Timestamp:HH:mm:ss} {Level:u3}] |{SrcContext}| {Message}{NewLine}{Exception}",
                    rollingInterval: RollingInterval.Day,
                    rollOnFileSizeLimit: true))
            .WriteTo.Async(console =>
                console.Console(
                    outputTemplate:
                    "[{Timestamp:HH:mm:ss} {Level:u3}] |{SrcContext}| {Message}{NewLine}{Exception}"))
            .Enrich.With<ContextEnricher>()
#if DEBUG
            .MinimumLevel.Verbose()
#else
            .MinimumLevel.Information()
#endif
            .CreateLogger();
    }
}

public sealed class ContextEnricher : ILogEventEnricher
{
    private const int MaxLength = 24;
    private const string EmptyContext = "NULL";

    private static readonly ConcurrentDictionary<string, string> FormattedCache = new();

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        var (_, value) = logEvent.Properties.FirstOrDefault(x => x.Key == Constants.SourceContextPropertyName);
        var raw = value?.ToString().Replace("\"", "") ?? EmptyContext;

        var formatted = FormattedCache.GetOrAdd(raw, static key =>
        {
            var ctx = key.AsSpan();
            if (ctx.Length > MaxLength)
                ctx = ctx[..MaxLength];

            int ctxLen = ctx.Length;
            return string.Create(MaxLength, (key, ctxLen), static (span, state) =>
            {
                span.Fill(' ');
                var src = state.key.AsSpan();
                if (src.Length > span.Length)
                    src = src[..span.Length];
                int padding = state.ctxLen < span.Length
                    ? (int)Math.Ceiling((double)(span.Length - state.ctxLen) / 2)
                    : 0;
                src.CopyTo(span[padding..]);
            });
        });

        var eventType = propertyFactory.CreateProperty("SrcContext", formatted);
        logEvent.AddPropertyIfAbsent(eventType);
    }
}
