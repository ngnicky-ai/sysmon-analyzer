namespace SysmonAnalyzer.Models;

public enum EventCategory { Process, Network, File, Registry, Module, Other }

public sealed record EventTypeInfo(int Id, string Name, string Korean, Color Color, EventCategory Category);

/// <summary>Sysmon 이벤트 ID별 이름/색상/분류 및 요약 문자열 생성.</summary>
public static class EventCatalog
{
    private static readonly Dictionary<int, EventTypeInfo> Map = new()
    {
        [1] = new(1, "ProcessCreate", "프로세스 생성", Color.FromArgb(46, 160, 67), EventCategory.Process),
        [2] = new(2, "FileCreateTime", "파일 생성시간 변경", Color.FromArgb(214, 158, 46), EventCategory.File),
        [3] = new(3, "NetworkConnect", "네트워크 연결", Color.FromArgb(31, 111, 235), EventCategory.Network),
        [4] = new(4, "SysmonState", "Sysmon 상태 변경", Color.FromArgb(128, 128, 128), EventCategory.Other),
        [5] = new(5, "ProcessTerminate", "프로세스 종료", Color.FromArgb(110, 118, 129), EventCategory.Process),
        [6] = new(6, "DriverLoad", "드라이버 로드", Color.FromArgb(137, 87, 229), EventCategory.Module),
        [7] = new(7, "ImageLoad", "이미지(DLL) 로드", Color.FromArgb(27, 153, 139), EventCategory.Module),
        [8] = new(8, "CreateRemoteThread", "원격 스레드 생성", Color.FromArgb(207, 34, 46), EventCategory.Process),
        [9] = new(9, "RawAccessRead", "Raw 디스크 읽기", Color.FromArgb(188, 76, 0), EventCategory.File),
        [10] = new(10, "ProcessAccess", "프로세스 접근", Color.FromArgb(230, 90, 60), EventCategory.Process),
        [11] = new(11, "FileCreate", "파일 생성", Color.FromArgb(191, 135, 0), EventCategory.File),
        [12] = new(12, "RegistryObject", "레지스트리 키 생성/삭제", Color.FromArgb(130, 80, 223), EventCategory.Registry),
        [13] = new(13, "RegistryValueSet", "레지스트리 값 설정", Color.FromArgb(160, 100, 230), EventCategory.Registry),
        [14] = new(14, "RegistryRename", "레지스트리 이름 변경", Color.FromArgb(110, 64, 201), EventCategory.Registry),
        [15] = new(15, "FileCreateStreamHash", "파일 스트림 생성", Color.FromArgb(160, 110, 20), EventCategory.File),
        [16] = new(16, "ConfigChange", "Sysmon 설정 변경", Color.FromArgb(128, 128, 128), EventCategory.Other),
        [17] = new(17, "PipeCreated", "파이프 생성", Color.FromArgb(0, 140, 170), EventCategory.Other),
        [18] = new(18, "PipeConnected", "파이프 연결", Color.FromArgb(0, 120, 150), EventCategory.Other),
        [19] = new(19, "WmiEventFilter", "WMI 필터", Color.FromArgb(180, 60, 140), EventCategory.Other),
        [20] = new(20, "WmiEventConsumer", "WMI 컨슈머", Color.FromArgb(180, 60, 140), EventCategory.Other),
        [21] = new(21, "WmiEventConsumerToFilter", "WMI 바인딩", Color.FromArgb(180, 60, 140), EventCategory.Other),
        [22] = new(22, "DnsQuery", "DNS 질의", Color.FromArgb(9, 150, 200), EventCategory.Network),
        [23] = new(23, "FileDelete", "파일 삭제(보관)", Color.FromArgb(170, 70, 50), EventCategory.File),
        [24] = new(24, "ClipboardChange", "클립보드 변경", Color.FromArgb(100, 100, 160), EventCategory.Other),
        [25] = new(25, "ProcessTampering", "프로세스 변조", Color.FromArgb(200, 20, 60), EventCategory.Process),
        [26] = new(26, "FileDeleteDetected", "파일 삭제 탐지", Color.FromArgb(170, 70, 50), EventCategory.File),
        [27] = new(27, "FileBlockExecutable", "실행파일 차단", Color.FromArgb(200, 40, 40), EventCategory.File),
        [28] = new(28, "FileBlockShredding", "파일 파쇄 차단", Color.FromArgb(200, 40, 40), EventCategory.File),
        [29] = new(29, "FileExecutableDetected", "실행파일 탐지", Color.FromArgb(200, 110, 40), EventCategory.File),
        [255] = new(255, "Error", "Sysmon 오류", Color.FromArgb(200, 0, 0), EventCategory.Other),
    };

    public static EventTypeInfo Get(int id) =>
        Map.TryGetValue(id, out var info) ? info : new(id, $"Event{id}", $"이벤트 {id}", Color.Gray, EventCategory.Other);

    public static string CategoryName(EventCategory c) => c switch
    {
        EventCategory.Process => "프로세스",
        EventCategory.Network => "네트워크",
        EventCategory.File => "파일",
        EventCategory.Registry => "레지스트리",
        EventCategory.Module => "모듈/드라이버",
        _ => "기타",
    };

    public static string Summarize(SysmonEvent e)
    {
        switch (e.EventId)
        {
            case 1:
                return $"{e.Get("CommandLine")}  ← {SysmonEvent.FileName(e.Get("ParentImage"))}";
            case 2:
                return $"{e.Get("TargetFilename")}  ({e.Get("PreviousCreationUtcTime")} → {e.Get("CreationUtcTime")})";
            case 3:
                {
                    var dir = e.Get("Initiated").Equals("true", StringComparison.OrdinalIgnoreCase) ? "→" : "⇠";
                    var host = e.Get("DestinationHostname");
                    return $"{e.Get("Protocol")} {e.Get("SourceIp")}:{e.Get("SourcePort")} {dir} {e.Get("DestinationIp")}:{e.Get("DestinationPort")}" +
                           (string.IsNullOrEmpty(host) || host == "-" ? "" : $" ({host})");
                }
            case 4:
                return $"State={e.Get("State")} Version={e.Get("Version")}";
            case 5:
                return e.Get("Image");
            case 6:
                return $"{e.Get("ImageLoaded")}  (Signed={e.Get("Signed")}, {e.Get("Signature")})";
            case 7:
                return $"{e.Get("ImageLoaded")}  (Signed={e.Get("Signed")})";
            case 8:
                return $"{e.Get("SourceImage")} → {e.Get("TargetImage")}  StartAddress={e.Get("StartAddress")}";
            case 9:
                return $"{e.Get("Device")}";
            case 10:
                return $"{e.Get("SourceImage")} → {e.Get("TargetImage")}  Access={e.Get("GrantedAccess")}";
            case 11:
            case 15:
            case 23:
            case 26:
            case 27:
            case 28:
            case 29:
                return e.Get("TargetFilename");
            case 12:
            case 13:
            case 14:
                {
                    var details = e.Get("Details");
                    var newName = e.Get("NewName");
                    return $"{e.Get("EventType")} {e.Get("TargetObject")}" +
                           (string.IsNullOrEmpty(details) ? "" : $" = {details}") +
                           (string.IsNullOrEmpty(newName) ? "" : $" → {newName}");
                }
            case 16:
                return $"{e.Get("Configuration")} {e.Get("ConfigurationFileHash")}";
            case 17:
            case 18:
                return e.Get("PipeName");
            case 19:
            case 20:
            case 21:
                return $"{e.Get("Operation")} {e.Get("Name")} {e.Get("Query")}{e.Get("Destination")}{e.Get("Consumer")}";
            case 22:
                return $"{e.Get("QueryName")} → {e.Get("QueryResults")}";
            case 24:
                return e.Get("Hashes");
            case 25:
                return $"{e.Get("Type")} {e.Get("Image")}";
            default:
                return string.Join("  ", e.Data.Where(kv => kv.Key is not ("RuleName" or "UtcTime")).Take(4).Select(kv => $"{kv.Key}={kv.Value}"));
        }
    }
}
