namespace SysmonAnalyzer.Models;

/// <summary>ProcessGuid 단위의 프로세스 실행 세션.</summary>
public sealed class ProcessInfo
{
    public string Guid { get; init; } = "";
    public int Pid { get; set; }
    public string Image { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string CurrentDirectory { get; set; } = "";
    public string User { get; set; } = "";
    public string IntegrityLevel { get; set; } = "";
    public string Hashes { get; set; } = "";
    public string Company { get; set; } = "";
    public string Description { get; set; } = "";
    public string Product { get; set; } = "";
    public string FileVersion { get; set; } = "";
    public string OriginalFileName { get; set; } = "";
    public string LogonId { get; set; } = "";
    public string Computer { get; set; } = "";

    public string ParentGuid { get; set; } = "";
    public int ParentPid { get; set; }
    public string ParentImage { get; set; } = "";
    public string ParentCommandLine { get; set; } = "";

    public DateTime? Start { get; set; }
    public DateTime? End { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.MaxValue;
    public DateTime LastSeen { get; set; } = DateTime.MinValue;

    /// <summary>ProcessCreate(1) 이벤트가 존재하는지. 없으면 다른 이벤트로부터 추정한 스텁.</summary>
    public bool HasCreateEvent { get; set; }
    public SysmonEvent? CreateEvent { get; set; }

    public ProcessInfo? Parent { get; set; }
    public List<ProcessInfo> Children { get; } = new();

    /// <summary>이 프로세스가 주체인 이벤트.</summary>
    public List<SysmonEvent> Events { get; } = new();

    /// <summary>다른 프로세스가 이 프로세스를 대상으로 한 이벤트 (8, 10).</summary>
    public List<SysmonEvent> IncomingEvents { get; } = new();

    public List<Alert> Alerts { get; } = new();

    public string Name => string.IsNullOrEmpty(Image) ? "(알 수 없음)" : SysmonEvent.FileName(Image);

    public AlertLevel? MaxAlertLevel => Alerts.Count == 0 ? null : Alerts.Max(a => a.Level);

    public int NetworkCount => Events.Count(e => e.EventId == 3);

    public string Label => $"{Name} ({Pid})";

    public IEnumerable<ProcessInfo> Ancestors()
    {
        var seen = new HashSet<ProcessInfo>();
        for (var p = Parent; p != null && seen.Add(p); p = p.Parent)
            yield return p;
    }

    public IEnumerable<ProcessInfo> Descendants()
    {
        var seen = new HashSet<ProcessInfo> { this };
        var stack = new Stack<ProcessInfo>(Children);
        while (stack.Count > 0)
        {
            var p = stack.Pop();
            if (!seen.Add(p)) continue;
            yield return p;
            foreach (var c in p.Children) stack.Push(c);
        }
    }

    public override string ToString() => Label;
}
