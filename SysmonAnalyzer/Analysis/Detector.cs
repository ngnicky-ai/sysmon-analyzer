using System.Text.RegularExpressions;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Analysis;

/// <summary>
/// 간단한 규칙 기반 의심 행위 탐지. 분석 시작점을 빠르게 찾기 위한 용도이며
/// 오탐/미탐이 있을 수 있다.
/// </summary>
public static class Detector
{
    private static readonly HashSet<string> Shells = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "schtasks.exe", "sc.exe",
    };

    private static readonly HashSet<string> RiskyParents = new(StringComparer.OrdinalIgnoreCase)
    {
        // 오피스/문서
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "visio.exe",
        "acrord32.exe", "acrobat.exe", "hwp.exe", "hword.exe",
        // 웹/서버
        "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe", "php-cgi.exe",
        "hfs.exe", "sqlservr.exe", "java.exe", "javaw.exe", "node.exe",
        // 브라우저
        "iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    };

    private static readonly HashSet<string> ReconTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "netstat.exe",
        "nltest.exe", "quser.exe", "query.exe", "arp.exe", "route.exe", "hostname.exe", "nslookup.exe",
        "dsquery.exe", "klist.exe", "cmdkey.exe", "wevtutil.exe",
    };

    private static readonly HashSet<string> NetworkLolbins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "notepad.exe",
        "calc.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
    };

    private static readonly (Regex Pattern, string Rule, AlertLevel Level)[] CommandRules =
    {
        (new Regex(@"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase), "PowerShell 인코딩 명령", AlertLevel.High),
        (new Regex(@"(downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-expression|iex\s*\(|net\.webclient|start-bitstransfer)", RegexOptions.IgnoreCase), "스크립트 다운로드/실행", AlertLevel.High),
        (new Regex(@"-(w|window|windowstyle)\s+h(idden)?\b|-nop\b|-noprofile.*-exec(utionpolicy)?\s+bypass|-ep\s+bypass", RegexOptions.IgnoreCase), "PowerShell 은닉/우회 옵션", AlertLevel.Medium),
        (new Regex(@"certutil.*(-urlcache|-decode|-split)", RegexOptions.IgnoreCase), "certutil 악용", AlertLevel.High),
        (new Regex(@"bitsadmin.*/transfer", RegexOptions.IgnoreCase), "bitsadmin 다운로드", AlertLevel.High),
        (new Regex(@"mshta(\.exe)?\s+.*(http|javascript|vbscript)", RegexOptions.IgnoreCase), "mshta 원격 스크립트", AlertLevel.High),
        (new Regex(@"regsvr32.*/i:\s*http|scrobj\.dll", RegexOptions.IgnoreCase), "regsvr32 Squiblydoo", AlertLevel.High),
        (new Regex(@"rundll32.*(javascript:|http)", RegexOptions.IgnoreCase), "rundll32 스크립트 실행", AlertLevel.High),
        (new Regex(@"vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin.*delete", RegexOptions.IgnoreCase), "백업/섀도 복사본 삭제", AlertLevel.High),
        (new Regex(@"schtasks.*/create", RegexOptions.IgnoreCase), "예약 작업 생성", AlertLevel.Medium),
        (new Regex(@"reg(\.exe)?\s+add.*\\(run|runonce)\b", RegexOptions.IgnoreCase), "Run 키 등록", AlertLevel.Medium),
        (new Regex(@"net(1)?(\.exe)?\s+(user|localgroup)\s+.*/add", RegexOptions.IgnoreCase), "계정 추가", AlertLevel.High),
        (new Regex(@"wscript.*\.(vbs|js|jse|vbe)\b|cscript.*\.(vbs|js|jse|vbe)\b", RegexOptions.IgnoreCase), "스크립트 호스트 실행", AlertLevel.Low),
        (new Regex(@"(mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs\.dll.*minidump)", RegexOptions.IgnoreCase), "자격 증명 덤프", AlertLevel.High),
    };

    private static readonly Regex UserWritablePath = new(
        @"\\(temp|tmp|appdata\\local\\temp|downloads|users\\public|perflogs|\$recycle\.bin)\\|\\appdata\\(roaming|local)\\[^\\]+\.exe$",
        RegexOptions.IgnoreCase);

    public static void Run(AnalysisResult r)
    {
        foreach (var p in r.Processes.Values)
        {
            if (p.HasCreateEvent) CheckProcess(r, p);
        }

        foreach (var c in r.Connections)
        {
            if (c.Process == null) continue;
            if (NetworkLolbins.Contains(c.ImageName))
            {
                Add(r, c.Process, AlertLevel.High, "LOLBin 네트워크 연결",
                    $"{c.ImageName} → {c.RemoteEndpoint} ({c.Protocol})", c.Event, dedupKey: c.RemoteEndpoint);
            }
            else if (c.Process.Image.Length > 0 && UserWritablePath.IsMatch(c.Process.Image) && c.Outbound)
            {
                Add(r, c.Process, AlertLevel.Medium, "사용자 쓰기 가능 경로 프로세스의 외부 연결",
                    $"{c.Process.Image} → {c.RemoteEndpoint}", c.Event, dedupKey: c.RemoteEndpoint);
            }
        }

        foreach (var e in r.Events)
        {
            switch (e.EventId)
            {
                case 8:
                    Add(r, Proc(r, e), AlertLevel.High, "원격 스레드 생성",
                        $"{SysmonEvent.FileName(e.Get("SourceImage"))} → {SysmonEvent.FileName(e.Get("TargetImage"))}", e);
                    break;
                case 10 when e.Get("TargetImage").EndsWith("lsass.exe", StringComparison.OrdinalIgnoreCase):
                    Add(r, Proc(r, e), AlertLevel.High, "LSASS 메모리 접근",
                        $"{e.Get("SourceImage")} Access={e.Get("GrantedAccess")}", e, dedupKey: e.Get("GrantedAccess"));
                    break;
                case 6 when !AnalysisResult.IsTrue(e.Get("Signed")):
                    // 부팅 초기에는 카탈로그를 못 읽어 SignatureStatus=Unavailable 인 경우가 흔하다
                    if (e.Get("SignatureStatus").Equals("Unavailable", StringComparison.OrdinalIgnoreCase) &&
                        e.Get("ImageLoaded").StartsWith(@"C:\Windows\System32\drivers\", StringComparison.OrdinalIgnoreCase))
                        Add(r, null, AlertLevel.Low, "드라이버 서명 확인 불가", e.Get("ImageLoaded"), e);
                    else
                        Add(r, null, AlertLevel.High, "서명되지 않은 드라이버 로드", $"{e.Get("ImageLoaded")} ({e.Get("SignatureStatus")})", e);
                    break;
                case 2 when UserWritablePath.IsMatch(e.Get("TargetFilename")) &&
                            Regex.IsMatch(e.Get("TargetFilename"), @"\.(exe|dll|ps1|vbs|js|bat|cmd|scr)$", RegexOptions.IgnoreCase):
                    Add(r, Proc(r, e), AlertLevel.Low, "실행 파일 생성시간 변경(Timestomp 의심)",
                        e.Get("TargetFilename"), e, dedupKey: e.Get("TargetFilename"));
                    break;
                case 25:
                    Add(r, Proc(r, e), AlertLevel.High, "프로세스 변조(Hollowing 등)", $"{e.Get("Type")} {e.Get("Image")}", e);
                    break;
                case 19:
                case 20:
                case 21:
                    Add(r, Proc(r, e), AlertLevel.Medium, "WMI 영구 이벤트 구독", e.Summary, e);
                    break;
                case 13 when Regex.IsMatch(e.Get("TargetObject"), @"\\CurrentVersion\\(Run|RunOnce)\\", RegexOptions.IgnoreCase):
                    Add(r, Proc(r, e), AlertLevel.Medium, "Run 키 자동 실행 등록", $"{e.Get("TargetObject")} = {e.Get("Details")}", e);
                    break;
                case 4 when !e.Get("State").Equals("Started", StringComparison.OrdinalIgnoreCase):
                    Add(r, null, AlertLevel.Medium, "Sysmon 서비스 상태 변경", $"State={e.Get("State")}", e);
                    break;
                case 16:
                    Add(r, null, AlertLevel.Low, "Sysmon 설정 변경", e.Summary, e);
                    break;
            }
        }

        r.Alerts.Sort((a, b) => b.Level != a.Level ? b.Level.CompareTo(a.Level) : a.Time.CompareTo(b.Time));
    }

    private static ProcessInfo? Proc(AnalysisResult r, SysmonEvent e) =>
        r.Processes.TryGetValue(e.ProcessGuid, out var p) ? p : null;

    private static void CheckProcess(AnalysisResult r, ProcessInfo p)
    {
        var e = p.CreateEvent!;
        var name = p.Name;
        var parentName = SysmonEvent.FileName(p.ParentImage);

        if (RiskyParents.Contains(parentName) && (Shells.Contains(name) || ReconTools.Contains(name)))
            Add(r, p, AlertLevel.High, "의심스러운 부모-자식 관계",
                $"{parentName} → {name}: {p.CommandLine}", e);

        // 쉘이 쉘을 띄운 뒤 정찰 명령을 수행하는 패턴
        if (ReconTools.Contains(name))
        {
            var level = Shells.Contains(parentName) ? AlertLevel.Medium : AlertLevel.Low;
            Add(r, p, level, "시스템 정찰 명령", $"{parentName} → {p.CommandLine}", e);
        }

        foreach (var (pattern, rule, level) in CommandRules)
            if (pattern.IsMatch(p.CommandLine))
                Add(r, p, level, rule, p.CommandLine, e);

        if (UserWritablePath.IsMatch(p.Image))
            Add(r, p, AlertLevel.Medium, "사용자 쓰기 가능 경로에서 실행", p.Image, e);

        // 알려진 시스템 파일명인데 경로가 System32/SysWOW64가 아님 (위장)
        if (name.ToLowerInvariant() is "svchost.exe" or "lsass.exe" or "csrss.exe" or "services.exe" or "smss.exe" or "winlogon.exe" or "explorer.exe" &&
            !Regex.IsMatch(p.Image, @"^[a-z]:\\windows\\(system32|syswow64|explorer\.exe)", RegexOptions.IgnoreCase))
            Add(r, p, AlertLevel.High, "시스템 프로세스 위장(비정상 경로)", p.Image, e);

        if (name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
            parentName.Length > 0 && !parentName.Equals("services.exe", StringComparison.OrdinalIgnoreCase) &&
            !parentName.Equals("MsMpEng.exe", StringComparison.OrdinalIgnoreCase))
            Add(r, p, AlertLevel.Medium, "비정상 부모의 svchost", $"{parentName} → svchost.exe", e);
    }

    private static void Add(AnalysisResult r, ProcessInfo? p, AlertLevel level, string rule, string detail,
        SysmonEvent e, string? dedupKey = null)
    {
        // 같은 프로세스 + 같은 규칙 + 같은 키는 한 번만
        if (p != null && p.Alerts.Any(a => a.Rule == rule && (dedupKey == null || a.Detail.Contains(dedupKey))))
            return;
        var alert = new Alert { Level = level, Rule = rule, Detail = detail, Time = e.Time, Process = p, Event = e };
        p?.Alerts.Add(alert);
        r.Alerts.Add(alert);
    }
}
