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
                    "[{Timestamp:HH:mm:ss} {Level:u3}] |{SrcContext}| {Message:lj}{NewLine}{Exception}",
                    rollingInterval: RollingInterval.Day,
                    rollOnFileSizeLimit: true))
            .WriteTo.Async(console =>
                console.Console(
                    outputTemplate:
                    "[{Timestamp:HH:mm:ss} {Level:u3}] |{SrcContext}| {Message:lj}{NewLine}{Exception}"))
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
        var raw = logEvent.Properties.TryGetValue(Constants.SourceContextPropertyName, out var value) &&
                  value is ScalarValue { Value: string sourceContext }
            ? sourceContext
            : EmptyContext;

        var formatted = FormattedCache.GetOrAdd(raw, static key =>
        {
            var contextLength = Math.Min(key.Length, MaxLength);
            return string.Create(MaxLength, (key, contextLength), static (span, state) =>
            {
                span.Fill(' ');
                var src = state.key.AsSpan();
                if (src.Length > span.Length)
                    src = src[..span.Length];

                var padding = (span.Length - state.contextLength + 1) / 2;
                src.CopyTo(span[padding..]);
            });
        });

        var eventType = propertyFactory.CreateProperty("SrcContext", formatted);
        logEvent.AddPropertyIfAbsent(eventType);
    }
}
