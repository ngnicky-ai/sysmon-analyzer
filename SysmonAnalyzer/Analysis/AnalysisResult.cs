using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Analysis;

/// <summary>로드한 이벤트로부터 프로세스 관계, 네트워크 연결, 탐지 결과를 구성한다.</summary>
public sealed class AnalysisResult
{
    public List<SysmonEvent> Events { get; } = new();
    public Dictionary<string, ProcessInfo> Processes { get; } = new();
    public List<ProcessInfo> Roots { get; } = new();
    public List<NetConnection> Connections { get; } = new();
    public List<Alert> Alerts { get; } = new();
    public HashSet<string> LocalIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Sources { get; } = new();
    public DateTime? First { get; private set; }
    public DateTime? Last { get; private set; }

    public static AnalysisResult Empty { get; } = new();

    public static AnalysisResult Build(IEnumerable<SysmonEvent> events, IEnumerable<string> sources)
    {
        var r = new AnalysisResult();
        r.Sources.AddRange(sources);
        r.Events.AddRange(events.OrderBy(e => e.Time).ThenBy(e => e.RecordId));
        for (int i = 0; i < r.Events.Count; i++) r.Events[i].Index = i;
        if (r.Events.Count > 0)
        {
            r.First = r.Events[0].Time;
            r.Last = r.Events[^1].Time;
        }

        r.BuildProcesses();
        r.BuildConnections();
        Detector.Run(r);
        return r;
    }

    private ProcessInfo GetOrCreate(string guid, SysmonEvent source)
    {
        if (!Processes.TryGetValue(guid, out var p))
        {
            p = new ProcessInfo { Guid = guid, Computer = source.Computer };
            Processes[guid] = p;
        }
        return p;
    }

    private void BuildProcesses()
    {
        foreach (var e in Events)
        {
            var guid = e.ProcessGuid;
            if (string.IsNullOrEmpty(guid)) continue;

            var p = GetOrCreate(guid, e);
            p.Events.Add(e);
            if (e.Time < p.FirstSeen) p.FirstSeen = e.Time;
            if (e.Time > p.LastSeen) p.LastSeen = e.Time;
            if (string.IsNullOrEmpty(p.Image)) p.Image = e.Image;
            if (p.Pid == 0) p.Pid = e.ProcessId;
            if (string.IsNullOrEmpty(p.User) && e.EventId != 1) p.User = e.Get("User");

            switch (e.EventId)
            {
                case 1:
                    FillFromCreate(p, e);
                    break;
                case 5:
                    p.End = e.Time;
                    break;
                case 8:
                case 10:
                    var tg = e.TargetProcessGuid;
                    if (!string.IsNullOrEmpty(tg))
                    {
                        var t = GetOrCreate(tg, e);
                        t.IncomingEvents.Add(e);
                        if (string.IsNullOrEmpty(t.Image)) t.Image = e.Get("TargetImage");
                        if (t.Pid == 0) t.Pid = e.GetInt("TargetProcessId");
                    }
                    break;
            }
        }

        // 부모 스텁 생성: ProcessCreate만 있고 부모의 이벤트가 없는 경우
        foreach (var p in Processes.Values.ToList())
        {
            if (string.IsNullOrEmpty(p.ParentGuid) || Processes.ContainsKey(p.ParentGuid)) continue;
            Processes[p.ParentGuid] = new ProcessInfo
            {
                Guid = p.ParentGuid,
                Pid = p.ParentPid,
                Image = p.ParentImage,
                CommandLine = p.ParentCommandLine,
                Computer = p.Computer,
            };
        }

        // 부모-자식 연결
        foreach (var p in Processes.Values)
        {
            if (p.FirstSeen == DateTime.MaxValue && p.Start.HasValue) p.FirstSeen = p.Start.Value;
            if (!string.IsNullOrEmpty(p.ParentGuid) && p.ParentGuid != p.Guid &&
                Processes.TryGetValue(p.ParentGuid, out var parent))
            {
                p.Parent = parent;
                parent.Children.Add(p);
            }
        }

        // 스텁 부모의 시작 시각은 가장 이른 자식 생성 시각으로 추정
        foreach (var p in Processes.Values.Where(p => p.FirstSeen == DateTime.MaxValue))
            p.FirstSeen = p.Children.Count > 0 ? p.Children.Min(c => c.FirstSeen) : (First ?? DateTime.MinValue);

        // 순환 방지: 조상 체인에 자신이 다시 나오면 끊는다
        foreach (var p in Processes.Values)
        {
            var seen = new HashSet<ProcessInfo> { p };
            for (var a = p.Parent; a != null; a = a.Parent)
            {
                if (!seen.Add(a))
                {
                    p.Parent!.Children.Remove(p);
                    p.Parent = null;
                    break;
                }
            }
        }

        foreach (var p in Processes.Values)
            p.Children.Sort((a, b) => a.FirstSeen.CompareTo(b.FirstSeen));
        Roots.AddRange(Processes.Values.Where(p => p.Parent == null).OrderBy(p => p.FirstSeen));
    }

    private static void FillFromCreate(ProcessInfo p, SysmonEvent e)
    {
        p.HasCreateEvent = true;
        p.CreateEvent = e;
        p.Start = e.Time;
        p.Image = e.Get("Image");
        p.Pid = e.GetInt("ProcessId");
        p.CommandLine = e.Get("CommandLine");
        p.CurrentDirectory = e.Get("CurrentDirectory");
        p.User = e.Get("User");
        p.IntegrityLevel = e.Get("IntegrityLevel");
        p.Hashes = e.Get("Hashes");
        p.Company = e.Get("Company");
        p.Description = e.Get("Description");
        p.Product = e.Get("Product");
        p.FileVersion = e.Get("FileVersion");
        p.OriginalFileName = e.Get("OriginalFileName");
        p.LogonId = e.Get("LogonId");
        p.ParentGuid = SysmonEvent.NormalizeGuid(e.Get("ParentProcessGuid"));
        p.ParentPid = e.GetInt("ParentProcessId");
        p.ParentImage = e.Get("ParentImage");
        p.ParentCommandLine = e.Get("ParentCommandLine");
    }

    private void BuildConnections()
    {
        var raw = Events.Where(e => e.EventId == 3).ToList();
        // 로컬 IP 추정: 아웃바운드(Initiated=true) 연결의 출발지 IP
        foreach (var e in raw)
            if (IsTrue(e.Get("Initiated"))) LocalIps.Add(e.Get("SourceIp"));

        foreach (var e in raw)
        {
            Processes.TryGetValue(e.ProcessGuid, out var proc);
            var c = new NetConnection
            {
                Event = e,
                Process = proc,
                Protocol = e.Get("Protocol"),
                Initiated = IsTrue(e.Get("Initiated")),
                SourceIp = e.Get("SourceIp"),
                SourcePort = e.GetInt("SourcePort"),
                DestIp = e.Get("DestinationIp"),
                DestPort = e.GetInt("DestinationPort"),
                DestHostname = e.Get("DestinationHostname"),
                DestPortName = e.Get("DestinationPortName"),
            };
            bool outbound = c.Initiated || (!LocalIps.Contains(c.DestIp) && LocalIps.Contains(c.SourceIp));
            if (!c.Initiated && LocalIps.Contains(c.DestIp)) outbound = false;
            c.Outbound = outbound;
            if (outbound)
            {
                c.LocalIp = c.SourceIp; c.LocalPort = c.SourcePort;
                c.RemoteIp = c.DestIp; c.RemotePort = c.DestPort;
            }
            else
            {
                c.LocalIp = c.DestIp; c.LocalPort = c.DestPort;
                c.RemoteIp = c.SourceIp; c.RemotePort = c.SourcePort;
            }
            Connections.Add(c);
        }
    }

    public static bool IsTrue(string s) => s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1";

    public IEnumerable<string> Computers => Events.Select(e => e.Computer).Where(c => c.Length > 0).Distinct();
}
