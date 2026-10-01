using System.Net;
using System.Text;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Analysis;

/// <summary>분석 결과 요약을 단일 HTML 파일로 생성.</summary>
public static class ReportWriter
{
    public static string Build(AnalysisResult r)
    {
        var sb = new StringBuilder();
        string H(string s) => WebUtility.HtmlEncode(s);

        sb.Append("""
<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sysmon 분석 보고서</title>
<style>
body{font-family:'Malgun Gothic',sans-serif;margin:24px;color:#1f2328;background:#f6f8fa}
h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}
.meta{color:#656d76}.cards{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.card{background:#fff;border:1px solid #d0d7de;border-left:4px solid #0969da;padding:10px 14px;min-width:160px}
.card b{display:block;font-size:22px}
table{border-collapse:collapse;background:#fff;width:100%;font-size:13px;margin-top:8px}
th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;vertical-align:top;word-break:break-all}
th{background:#eef1f4}.High{color:#cf222e;font-weight:bold}.Medium{color:#db7600}.Low{color:#9a8c14}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px}
.tree{font-family:Consolas,monospace;font-size:12px;background:#fff;border:1px solid #d0d7de;padding:10px;white-space:pre;overflow:auto;max-height:600px}
</style></head><body>
""");
        sb.Append($"<h1>Sysmon 분석 보고서</h1><div class='meta'>원본: {H(string.Join(", ", r.Sources))} · 생성: {DateTime.Now:yyyy-MM-dd HH:mm:ss} · 기간(UTC): {r.First:yyyy-MM-dd HH:mm:ss} ~ {r.Last:yyyy-MM-dd HH:mm:ss}</div>");
        sb.Append("<div class='cards'>");
        void Card(string k, string v) => sb.Append($"<div class='card'>{H(k)}<b>{H(v)}</b></div>");
        Card("전체 이벤트", r.Events.Count.ToString("N0"));
        Card("프로세스(GUID)", r.Processes.Count.ToString("N0"));
        Card("네트워크 연결", r.Connections.Count.ToString("N0"));
        Card("고유 원격 IP", r.Connections.Select(c => c.RemoteIp).Distinct().Count().ToString("N0"));
        Card("탐지 경고", r.Alerts.Count.ToString("N0"));
        Card("호스트", string.Join(", ", r.Computers));
        sb.Append("</div>");

        void Table(string title, IEnumerable<(string, int)> rows, string col)
        {
            sb.Append($"<div><h2>{H(title)}</h2><table><tr><th>{H(col)}</th><th style='width:80px'>건수</th></tr>");
            foreach (var (k, v) in rows) sb.Append($"<tr><td>{H(k)}</td><td>{v:N0}</td></tr>");
            sb.Append("</table></div>");
        }

        sb.Append("<h2>탐지 경고</h2><table><tr><th>위험도</th><th>시각(UTC)</th><th>규칙</th><th>프로세스</th><th>내용</th></tr>");
        foreach (var a in r.Alerts.Take(300))
            sb.Append($"<tr><td class='{a.Level}'>{a.LevelText}</td><td>{a.Time:yyyy-MM-dd HH:mm:ss}</td><td>{H(a.Rule)}</td><td>{H(a.Process?.Label ?? "-")}</td><td>{H(a.Detail)}</td></tr>");
        sb.Append("</table>");

        sb.Append("<div class='grid'>");
        Table("이벤트 유형", r.Events.GroupBy(e => e.EventId).OrderByDescending(g => g.Count())
            .Select(g => ($"[{g.Key}] {EventCatalog.Get(g.Key).Korean}", g.Count())), "유형");
        Table("Top 실행 파일(생성)", r.Events.Where(e => e.EventId == 1).GroupBy(e => e.Get("Image"), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).Take(20).Select(g => (g.Key, g.Count())), "실행 파일");
        Table("Top 부모 → 자식", r.Events.Where(e => e.EventId == 1)
            .GroupBy(e => $"{SysmonEvent.FileName(e.Get("ParentImage"))} → {SysmonEvent.FileName(e.Get("Image"))}", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).Take(20).Select(g => (g.Key, g.Count())), "관계");
        Table("Top 원격 IP", r.Connections.GroupBy(c => c.RemoteIp).OrderByDescending(g => g.Count()).Take(20)
            .Select(g => (g.Key + (IpUtil.IsPublic(g.Key) ? " (공인)" : ""), g.Count())), "IP");
        Table("Top 서비스 포트", r.Connections.GroupBy(c => $"{c.ServicePort}/{c.Protocol}").OrderByDescending(g => g.Count()).Take(20)
            .Select(g => (g.Key, g.Count())), "포트");
        Table("Top 프로세스 → 원격 IP:Port", r.Connections.GroupBy(c => $"{c.ImageName} → {c.RemoteEndpoint}").OrderByDescending(g => g.Count()).Take(20)
            .Select(g => (g.Key, g.Count())), "연결");
        sb.Append("</div>");

        // 경고 프로세스의 계층 경로
        var flagged = r.Processes.Values.Where(p => p.Alerts.Count > 0).ToList();
        if (flagged.Count > 0)
        {
            var keep = new HashSet<ProcessInfo>(flagged.SelectMany(p => p.Ancestors().Append(p)));
            sb.Append("<h2>경고 프로세스 계층 (조상 경로 포함)</h2><div class='tree'>");
            foreach (var root in r.Roots.Where(keep.Contains))
                WriteTree(sb, root, keep, "", true, true);
            sb.Append("</div>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static void WriteTree(StringBuilder sb, ProcessInfo p, HashSet<ProcessInfo> keep, string indent, bool last, bool root)
    {
        var mark = p.MaxAlertLevel is { } lv ? $" <span class='{lv}'>⚠ {WebUtility.HtmlEncode(string.Join(", ", p.Alerts.Select(a => a.Rule).Distinct()))}</span>" : "";
        var cmd = p.CommandLine.Length > 160 ? p.CommandLine[..160] + "…" : p.CommandLine;
        sb.Append(WebUtility.HtmlEncode(indent + (root ? "" : last ? "└─ " : "├─ ") + $"{p.Name} ({p.Pid})  {cmd}")).Append(mark).Append('\n');
        var kids = p.Children.Where(keep.Contains).ToList();
        for (int i = 0; i < kids.Count; i++)
            WriteTree(sb, kids[i], keep, indent + (root ? "" : last ? "   " : "│  "), i == kids.Count - 1, false);
    }
}
