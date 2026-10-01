using System.Text;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>탭 사이 이동(드릴다운)을 담당하는 메인 폼 기능.</summary>
public interface INavigator
{
    void ShowProcessTree(ProcessInfo p);
    void ShowProcessTrack(ProcessInfo p);
    void ShowProcessTrackByImage(string image);
    void ShowEvents(string? text = null, int? eventId = null, DateTime? from = null, DateTime? to = null);
    void ShowNetwork(string? filter);
    void ShowAlerts();
}

public static class EventFormat
{
    /// <summary>이벤트의 전체 필드를 사람이 읽기 좋은 텍스트로.</summary>
    public static string Details(SysmonEvent? e)
    {
        if (e == null) return "";
        var info = EventCatalog.Get(e.EventId);
        var sb = new StringBuilder();
        sb.AppendLine($"[{e.EventId}] {info.Name} - {info.Korean}");
        sb.AppendLine($"시각(UTC): {e.Time:yyyy-MM-dd HH:mm:ss.fff}    컴퓨터: {e.Computer}    RecordID: {e.RecordId}    원본: {e.SourceFile}");
        sb.AppendLine(new string('─', 80));
        int w = e.Data.Keys.DefaultIfEmpty("").Max(k => k.Length);
        foreach (var kv in e.Data)
            sb.AppendLine($"{kv.Key.PadRight(w)} : {kv.Value}");
        return sb.ToString().Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");
    }

    public static string Csv(string s)
    {
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }
}
