using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Parsing;

/// <summary>
/// Sysmon 이벤트 로더. .evtx 파일, 로컬 Sysmon 채널, wevtutil XML 출력(.xml)을 지원한다.
/// EVTX는 (EventID, Version)별로 처음 한 번만 XML을 파싱해 필드 이름을 얻고,
/// 이후에는 EventRecord.Properties를 인덱스로 읽어 속도를 높인다.
/// </summary>
public static class EventLoader
{
    public const string SysmonChannel = "Microsoft-Windows-Sysmon/Operational";
    private const string SysmonProvider = "Microsoft-Windows-Sysmon";

    public static List<SysmonEvent> LoadFile(string path, IProgress<string>? progress, CancellationToken ct)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext == ".xml"
            ? LoadXml(path, progress, ct)
            : LoadEventLog(path, PathType.FilePath, Path.GetFileName(path), progress, ct);
    }

    public static List<SysmonEvent> LoadLocalChannel(IProgress<string>? progress, CancellationToken ct) =>
        LoadEventLog(SysmonChannel, PathType.LogName, "로컬:" + SysmonChannel, progress, ct);

    private static List<SysmonEvent> LoadEventLog(string path, PathType type, string sourceName,
        IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<SysmonEvent>();
        var nameCache = new Dictionary<(int, byte), string[]>();
        var query = new EventLogQuery(path, type, $"*[System[Provider[@Name='{SysmonProvider}']]]");
        using var reader = new EventLogReader(query);
        int n = 0;
        for (EventRecord? rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
        {
            using (rec)
            {
                ct.ThrowIfCancellationRequested();
                var ev = Convert(rec, sourceName, nameCache);
                if (ev != null) result.Add(ev);
                if (++n % 2000 == 0) progress?.Report($"{sourceName}: {n:N0}건 읽는 중...");
            }
        }
        progress?.Report($"{sourceName}: {n:N0}건 읽음");
        return result;
    }

    private static SysmonEvent? Convert(EventRecord rec, string source, Dictionary<(int, byte), string[]> nameCache)
    {
        var key = (rec.Id, rec.Version ?? 0);
        IList<EventProperty>? props = null;
        try { props = rec.Properties; } catch { /* 일부 손상 레코드 */ }

        Dictionary<string, string> data;
        if (nameCache.TryGetValue(key, out var names) && props != null && props.Count == names.Length)
        {
            data = new Dictionary<string, string>(names.Length, StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < names.Length; i++)
                data[names[i]] = FormatValue(props[i].Value);
        }
        else
        {
            string xml;
            try { xml = rec.ToXml(); } catch { return null; }
            var parsed = ParseEventXml(xml, source);
            if (parsed == null) return null;
            data = parsed.Data;
            if (props != null && props.Count == data.Count && !nameCache.ContainsKey(key))
                nameCache[key] = data.Keys.ToArray();
            // XML 경로 결과에는 RecordId/Computer가 이미 들어 있다
            return parsed;
        }

        var time = ParseUtc(data.GetValueOrDefault("UtcTime")) ??
                   rec.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue;
        return new SysmonEvent
        {
            EventId = rec.Id,
            RecordId = rec.RecordId ?? 0,
            Computer = rec.MachineName ?? "",
            Time = time,
            SourceFile = source,
            Data = data,
        };
    }

    private static string FormatValue(object? v) => v switch
    {
        null => "",
        string s => s,
        Guid g => g.ToString("B"),
        DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
        byte[] b => System.Convert.ToHexString(b),
        _ => System.Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    private static DateTime? ParseUtc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        if (DateTime.TryParseExact(s, "yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            return t;
        if (DateTime.TryParse(s, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out t))
            return t;
        return null;
    }

    /// <summary>&lt;Event&gt; 요소 하나의 XML을 SysmonEvent로 변환.</summary>
    public static SysmonEvent? ParseEventXml(string xml, string source)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return ParseEventElement(doc.DocumentElement!, source);
    }

    private static SysmonEvent? ParseEventElement(XmlElement ev, string source)
    {
        int id = 0; long rid = 0; string computer = "", provider = ""; DateTime? created = null;
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (XmlNode section in ev.ChildNodes)
        {
            if (section is not XmlElement se) continue;
            if (se.LocalName == "System")
            {
                foreach (XmlNode n in se.ChildNodes)
                {
                    if (n is not XmlElement el) continue;
                    switch (el.LocalName)
                    {
                        case "Provider": provider = el.GetAttribute("Name"); break;
                        case "EventID": int.TryParse(el.InnerText, out id); break;
                        case "EventRecordID": long.TryParse(el.InnerText, out rid); break;
                        case "Computer": computer = el.InnerText; break;
                        case "TimeCreated":
                            if (DateTime.TryParse(el.GetAttribute("SystemTime"), CultureInfo.InvariantCulture,
                                    DateTimeStyles.AdjustToUniversal, out var tc))
                                created = tc;
                            break;
                    }
                }
            }
            else if (se.LocalName == "EventData")
            {
                foreach (XmlNode n in se.ChildNodes)
                    if (n is XmlElement d && d.LocalName == "Data")
                        data[d.GetAttribute("Name")] = d.InnerText;
            }
        }
        if (!string.IsNullOrEmpty(provider) && !provider.Equals(SysmonProvider, StringComparison.OrdinalIgnoreCase))
            return null;
        return new SysmonEvent
        {
            EventId = id,
            RecordId = rid,
            Computer = computer,
            Time = ParseUtc(data.GetValueOrDefault("UtcTime")) ?? created ?? DateTime.MinValue,
            SourceFile = source,
            Data = data,
        };
    }

    /// <summary>
    /// BOM이 있으면 그에 따르고, 없으면 UTF-8 → 실패 시 시스템 ANSI 코드페이지(예: CP949)로 디코딩.
    /// wevtutil 출력은 BOM 없이 ANSI 코드페이지로 저장된다.
    /// </summary>
    private static string ReadText(string path)
    {
        var bytes = File.ReadAllBytes(path);
        bool bom = bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF) ||
                                         (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF));
        if (bom)
        {
            using var sr = new StreamReader(new MemoryStream(bytes), System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return sr.ReadToEnd();
        }
        try
        {
            return new System.Text.UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            return System.Text.Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage).GetString(bytes);
        }
    }

    /// <summary>wevtutil qe ... /f:xml 출력처럼 루트 없이 &lt;Event&gt;가 나열된 XML도 처리.</summary>
    private static List<SysmonEvent> LoadXml(string path, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<SysmonEvent>();
        var source = Path.GetFileName(path);
        var settings = new XmlReaderSettings { ConformanceLevel = ConformanceLevel.Fragment, IgnoreWhitespace = true, DtdProcessing = DtdProcessing.Ignore };
        var text = System.Text.RegularExpressions.Regex.Replace(ReadText(path), @"^\s*<\?xml[^>]*\?>", "");
        using var reader = XmlReader.Create(new StringReader(text), settings);
        var doc = new XmlDocument();
        int n = 0;
        while (!reader.EOF)
        {
            ct.ThrowIfCancellationRequested();
            if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Event")
            {
                if (doc.ReadNode(reader) is XmlElement el)
                {
                    var ev = ParseEventElement(el, source);
                    if (ev != null) result.Add(ev);
                    if (++n % 2000 == 0) progress?.Report($"{source}: {n:N0}건 읽는 중...");
                }
                continue;
            }
            reader.Read();
        }
        progress?.Report($"{source}: {n:N0}건 읽음");
        return result;
    }
}
