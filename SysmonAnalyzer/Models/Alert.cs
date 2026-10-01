namespace SysmonAnalyzer.Models;

public enum AlertLevel { Low = 1, Medium = 2, High = 3 }

/// <summary>규칙 기반 탐지 결과.</summary>
public sealed class Alert
{
    public AlertLevel Level { get; init; }
    public string Rule { get; init; } = "";
    public string Detail { get; init; } = "";
    public DateTime Time { get; init; }
    public ProcessInfo? Process { get; init; }
    public SysmonEvent? Event { get; init; }

    public string LevelText => Level switch
    {
        AlertLevel.High => "높음",
        AlertLevel.Medium => "중간",
        _ => "낮음",
    };

    public static Color LevelColor(AlertLevel level) => level switch
    {
        AlertLevel.High => Color.FromArgb(207, 34, 46),
        AlertLevel.Medium => Color.FromArgb(219, 118, 0),
        _ => Color.FromArgb(154, 140, 20),
    };
}

/// <summary>네트워크 연결(이벤트 3) 정규화 레코드.</summary>
public sealed class NetConnection
{
    public SysmonEvent Event { get; init; } = null!;
    public ProcessInfo? Process { get; init; }
    public DateTime Time => Event.Time;
    public string Image => Event.Image;
    public string ImageName => Event.ImageName;
    public string Protocol { get; init; } = "";
    public bool Initiated { get; init; }
    public string SourceIp { get; init; } = "";
    public int SourcePort { get; init; }
    public string DestIp { get; init; } = "";
    public int DestPort { get; init; }
    public string DestHostname { get; init; } = "";
    public string DestPortName { get; init; } = "";

    // 로컬 IP 집합으로 추정한 원격/로컬 측
    public string RemoteIp { get; set; } = "";
    public int RemotePort { get; set; }
    public string LocalIp { get; set; } = "";
    public int LocalPort { get; set; }
    public bool Outbound { get; set; }

    public string Direction => Outbound ? "아웃바운드" : "인바운드";

    /// <summary>서비스 포트: 아웃바운드면 원격 포트, 인바운드면 로컬(수신) 포트.</summary>
    public int ServicePort => Outbound ? RemotePort : LocalPort;
    public string RemoteEndpoint => IpUtil.Endpoint(RemoteIp, RemotePort);
}

public static class IpUtil
{
    public static string Endpoint(string ip, int port) => ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";

    /// <summary>사설/루프백/링크로컬/멀티캐스트/브로드캐스트가 아닌 공인 IP 여부.</summary>
    public static bool IsPublic(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
        if (System.Net.IPAddress.IsLoopback(addr)) return false;
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6Multicast) return false;
            if (addr.IsIPv4MappedToIPv6) return IsPublic(addr.MapToIPv4().ToString());
            var b0 = addr.GetAddressBytes()[0];
            if ((b0 & 0xFE) == 0xFC) return false; // fc00::/7 ULA
            return !addr.Equals(System.Net.IPAddress.IPv6None);
        }
        var b = addr.GetAddressBytes();
        return !(b[0] == 10 || b[0] == 0 || b[0] == 127 ||
                 (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                 (b[0] == 192 && b[1] == 168) ||
                 (b[0] == 169 && b[1] == 254) ||
                 (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
                 b[0] >= 224);
    }
}
