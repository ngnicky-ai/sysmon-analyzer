namespace SysmonAnalyzer.Models;

/// <summary>Sysmon 이벤트 한 건. EventData 필드는 이름→값 사전으로 보관한다.</summary>
public sealed class SysmonEvent
{
    public int Index { get; set; }
    public int EventId { get; init; }
    public long RecordId { get; init; }
    public DateTime Time { get; init; }
    public string Computer { get; init; } = "";
    public string SourceFile { get; init; } = "";
    public Dictionary<string, string> Data { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public string Get(string key) => Data.TryGetValue(key, out var v) ? v ?? "" : "";

    public int GetInt(string key) => int.TryParse(Get(key), out var v) ? v : 0;

    /// <summary>이벤트의 주체 프로세스 GUID (8/10번은 Source 프로세스).</summary>
    public string ProcessGuid
    {
        get
        {
            var g = EventId is 8 or 10 ? Get("SourceProcessGuid") : Get("ProcessGuid");
            return NormalizeGuid(g);
        }
    }

    /// <summary>원격 스레드/프로세스 접근의 대상 프로세스 GUID.</summary>
    public string TargetProcessGuid => EventId is 8 or 10 ? NormalizeGuid(Get("TargetProcessGuid")) : "";

    public string Image => EventId is 8 or 10 ? Get("SourceImage") : Get("Image");

    public int ProcessId => EventId is 8 or 10 ? GetInt("SourceProcessId") : GetInt("ProcessId");

    public string ImageName => FileName(Image);

    public string Summary => EventCatalog.Summarize(this);

    public static string NormalizeGuid(string g)
    {
        if (string.IsNullOrWhiteSpace(g)) return "";
        g = g.Trim().ToLowerInvariant();
        if (g == "{00000000-0000-0000-0000-000000000000}") return "";
        return g;
    }

    public static string FileName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        int i = path.LastIndexOfAny(new[] { '\\', '/' });
        return i >= 0 ? path[(i + 1)..] : path;
    }
}
