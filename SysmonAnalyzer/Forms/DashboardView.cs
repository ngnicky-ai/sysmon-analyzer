using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>메인 대시보드: 요약 카드 + 이벤트 추이 + 프로세스/IP/포트 통계 + 탐지 요약.</summary>
public sealed class DashboardView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;

    private readonly StatCard _cEvents = new() { Caption = "전체 이벤트" };
    private readonly StatCard _cRange = new() { Caption = "수집 기간 (UTC)" };
    private readonly StatCard _cProcs = new() { Caption = "프로세스 (세션/GUID)", AccentColor = EventCatalog.Get(1).Color };
    private readonly StatCard _cImages = new() { Caption = "고유 실행 파일", AccentColor = EventCatalog.Get(1).Color };
    private readonly StatCard _cConns = new() { Caption = "네트워크 연결", AccentColor = EventCatalog.Get(3).Color };
    private readonly StatCard _cIps = new() { Caption = "고유 원격 IP", AccentColor = EventCatalog.Get(3).Color };
    private readonly StatCard _cAlerts = new() { Caption = "탐지 경고", AccentColor = Alert.LevelColor(AlertLevel.High) };
    private readonly StatCard _cHosts = new() { Caption = "호스트", AccentColor = Ui.Muted };

    private readonly TimeHistogram _hist = new();
    private readonly BarChart _byId = new() { Title = "이벤트 유형별 분포", Subtitle = "클릭: 해당 유형 이벤트 보기" };
    private readonly BarChart _topProc = new() { Title = "Top 프로세스 (이벤트 수)", Subtitle = "클릭: 프로세스 추적", BarColor = EventCatalog.Get(1).Color };
    private readonly BarChart _topCreate = new() { Title = "Top 실행 파일 (생성 횟수)", Subtitle = "ProcessCreate 기준 · 클릭: 프로세스 추적", BarColor = Color.FromArgb(26, 127, 55) };
    private readonly BarChart _topPair = new() { Title = "Top 부모 → 자식 관계", Subtitle = "클릭: 이벤트 검색", BarColor = Color.FromArgb(130, 80, 223) };
    private readonly BarChart _topRemote = new() { Title = "Top 원격 IP", Subtitle = "클릭: 네트워크 탭 필터", BarColor = EventCatalog.Get(3).Color };
    private readonly BarChart _topPublic = new() { Title = "Top 외부(공인) IP", Subtitle = "사설/멀티캐스트 제외", BarColor = Color.FromArgb(207, 34, 46) };
    private readonly BarChart _topPort = new() { Title = "Top 서비스 포트", Subtitle = "아웃바운드=원격 포트, 인바운드=수신 포트", BarColor = Color.FromArgb(9, 150, 200) };
    private readonly BarChart _topEndpoint = new() { Title = "Top 연결 대상 (IP:Port)", Subtitle = "클릭: 네트워크 탭 필터", BarColor = Color.FromArgb(31, 111, 235) };
    private readonly BarChart _topNetProc = new() { Title = "Top 네트워크 사용 프로세스", Subtitle = "클릭: 네트워크 탭 필터", BarColor = Color.FromArgb(27, 153, 139) };
    private readonly BarChart _topUser = new() { Title = "Top 사용자 (프로세스 생성)", BarColor = Color.FromArgb(110, 118, 129) };
    private readonly BarChart _topDns = new() { Title = "Top DNS 질의", Subtitle = "이벤트 22", BarColor = Color.FromArgb(9, 150, 200) };
    private readonly ListView _alerts = Ui.NewListView(("위험도", 60), ("규칙", 220), ("프로세스", 150), ("시각(UTC)", 160), ("내용", 600));

    public DashboardView(INavigator nav)
    {
        _nav = nav;
        BackColor = Ui.Background;
        Dock = DockStyle.Fill;

        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(Ui.S(this, 10)) };
        Controls.Add(scroll);

        var table = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 12,
            BackColor = Ui.Background,
        };
        for (int i = 0; i < 12; i++) table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 12));

        int cardH = Ui.S(this, 88), chartH = Ui.S(this, 300);
        var cards = new[] { _cEvents, _cRange, _cProcs, _cImages, _cConns, _cIps, _cAlerts, _cHosts };
        int row = 0;
        // 카드 2줄 x 4개 (각 3칸)
        for (int i = 0; i < cards.Length; i++)
        {
            if (i % 4 == 0) { table.RowStyles.Add(new RowStyle(SizeType.Absolute, cardH)); if (i > 0) row++; }
            Place(table, cards[i], (i % 4) * 3, row, 3);
        }
        row++;
        table.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(this, 250)));
        Place(table, _hist, 0, row++, 12);

        void ChartRow(params Control[] cs)
        {
            table.RowStyles.Add(new RowStyle(SizeType.Absolute, chartH));
            int span = 12 / cs.Length;
            for (int i = 0; i < cs.Length; i++) Place(table, cs[i], i * span, row, span);
            row++;
        }
        ChartRow(_byId, _topProc, _topCreate);
        ChartRow(_topPair, _topUser, _topDns);
        ChartRow(_topRemote, _topPublic, _topPort);
        ChartRow(_topEndpoint, _topNetProc);

        var alertBox = new Panel { BackColor = Ui.Surface, Padding = new Padding(1) };
        var alertTitle = Ui.SectionTitle("탐지 경고 (상위 50건) · 더블클릭: 프로세스 트리로 이동");
        alertBox.Controls.Add(_alerts);
        alertBox.Controls.Add(alertTitle);
        table.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(this, 320)));
        Place(table, alertBox, 0, row++, 12);
        table.RowCount = row;

        scroll.Controls.Add(table);

        // 확대 배율(Ctrl+휠)에 맞춰 카드/차트 행 높이 조정 (생성 시점 = 100% 기준)
        float baseZoom = Ui.Zoom;
        var baseHeights = table.RowStyles.Cast<RowStyle>().Select(rs => (rs, h: rs.Height / baseZoom)).ToList();
        EventHandler onZoom = (_, _) =>
        {
            table.SuspendLayout();
            foreach (var (rs, h) in baseHeights) rs.Height = h * Ui.Zoom;
            table.ResumeLayout(true);
        };
        Ui.ZoomChanged += onZoom;
        Disposed += (_, _) => Ui.ZoomChanged -= onZoom;

        _cAlerts.CardClicked += (_, _) => _nav.ShowAlerts();
        _cConns.CardClicked += (_, _) => _nav.ShowNetwork(null);
        _cEvents.CardClicked += (_, _) => _nav.ShowEvents();
        _hist.BucketClicked += (_, range) => _nav.ShowEvents(from: range.From, to: range.To);
        _byId.ItemClicked += (_, it) => _nav.ShowEvents(eventId: (int)it.Tag!);
        _topProc.ItemClicked += (_, it) => _nav.ShowProcessTrackByImage((string)it.Tag!);
        _topCreate.ItemClicked += (_, it) => _nav.ShowProcessTrackByImage((string)it.Tag!);
        _topPair.ItemClicked += (_, it) => _nav.ShowEvents(text: (string)it.Tag!, eventId: 1);
        _topUser.ItemClicked += (_, it) => _nav.ShowEvents(text: (string)it.Tag!, eventId: 1);
        _topDns.ItemClicked += (_, it) => _nav.ShowEvents(text: (string)it.Tag!, eventId: 22);
        foreach (var c in new[] { _topRemote, _topPublic, _topEndpoint, _topNetProc })
            c.ItemClicked += (_, it) => _nav.ShowNetwork((string)it.Tag!);
        _topPort.ItemClicked += (_, it) => _nav.ShowNetwork(":" + it.Tag);
        _alerts.DoubleClick += (_, _) =>
        {
            if (_alerts.SelectedItems.Count > 0 && _alerts.SelectedItems[0].Tag is Alert { Process: { } p })
                _nav.ShowProcessTree(p);
        };
    }

    private static void Place(TableLayoutPanel t, Control c, int col, int row, int span)
    {
        c.Dock = DockStyle.Fill;
        c.Margin = new Padding(4);
        t.Controls.Add(c, col, row);
        t.SetColumnSpan(c, span);
    }

    public void Bind(AnalysisResult r)
    {
        _r = r;
        var ev = r.Events;
        _cEvents.Set(ev.Count.ToString("N0"), $"원본 {r.Sources.Count}개 · 유형 {ev.Select(e => e.EventId).Distinct().Count()}종");
        _cRange.Set(r.First.HasValue ? $"{(r.Last - r.First)!.Value.TotalHours:0.#}시간" : "-",
            r.First.HasValue ? $"{r.First:yyyy-MM-dd HH:mm} ~ {r.Last:MM-dd HH:mm}" : "");
        int created = r.Processes.Values.Count(p => p.HasCreateEvent);
        _cProcs.Set(r.Processes.Count.ToString("N0"), $"생성 이벤트 {created:N0} · 추정 {r.Processes.Count - created:N0}");
        _cImages.Set(r.Processes.Values.Where(p => p.Image.Length > 0).Select(p => p.Image.ToLowerInvariant()).Distinct().Count().ToString("N0"),
            $"루트 프로세스 {r.Roots.Count:N0}개");
        _cConns.Set(r.Connections.Count.ToString("N0"),
            $"아웃바운드 {r.Connections.Count(c => c.Outbound):N0} · 인바운드 {r.Connections.Count(c => !c.Outbound):N0}");
        var remotes = r.Connections.Select(c => c.RemoteIp).Distinct().ToList();
        _cIps.Set(remotes.Count.ToString("N0"), $"공인 IP {remotes.Count(IpUtil.IsPublic):N0}개");
        _cAlerts.Set(r.Alerts.Count.ToString("N0"),
            $"높음 {r.Alerts.Count(a => a.Level == AlertLevel.High)} · 중간 {r.Alerts.Count(a => a.Level == AlertLevel.Medium)} · 낮음 {r.Alerts.Count(a => a.Level == AlertLevel.Low)}");
        var hosts = r.Computers.ToList();
        _cHosts.Set(hosts.Count.ToString("N0"), string.Join(", ", hosts.Take(3)));

        _hist.SetEvents(ev);

        _byId.SetItems(ev.GroupBy(e => e.EventId).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem($"[{g.Key}] {EventCatalog.Get(g.Key).Korean}", g.Count(), g.Key, EventCatalog.Get(g.Key).Color)));

        _topProc.SetItems(r.Processes.Values.Where(p => p.Image.Length > 0)
            .GroupBy(p => p.Image, StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, Count: g.Sum(p => p.Events.Count)))
            .OrderByDescending(x => x.Count)
            .Select(x => new ChartItem(SysmonEvent.FileName(x.Key), x.Count, x.Key)));

        _topCreate.SetItems(ev.Where(e => e.EventId == 1)
            .GroupBy(e => e.Get("Image"), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(SysmonEvent.FileName(g.Key), g.Count(), g.Key)));

        _topPair.SetItems(ev.Where(e => e.EventId == 1)
            .GroupBy(e => $"{SysmonEvent.FileName(e.Get("ParentImage"))} → {SysmonEvent.FileName(e.Get("Image"))}", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key, g.Count(), SysmonEvent.FileName(g.First().Get("Image")))));

        _topUser.SetItems(ev.Where(e => e.EventId == 1 && e.Get("User").Length > 0)
            .GroupBy(e => e.Get("User"), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key, g.Count(), g.Key)));

        _topDns.SetItems(ev.Where(e => e.EventId == 22)
            .GroupBy(e => e.Get("QueryName"), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key, g.Count(), g.Key)));

        var conns = r.Connections;
        _topRemote.SetItems(conns.GroupBy(c => c.RemoteIp).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key, g.Count(), g.Key)));
        _topPublic.SetItems(conns.Where(c => IpUtil.IsPublic(c.RemoteIp)).GroupBy(c => c.RemoteIp).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key + HostSuffix(g), g.Count(), g.Key)));
        _topPort.SetItems(conns.GroupBy(c => (c.ServicePort, c.Protocol)).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem($"{g.Key.ServicePort}/{g.Key.Protocol}{PortName(g.Key.ServicePort)}", g.Count(), g.Key.ServicePort)));
        _topEndpoint.SetItems(conns.GroupBy(c => c.RemoteEndpoint).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key + HostSuffix(g), g.Count(), g.Key)));
        _topNetProc.SetItems(conns.GroupBy(c => c.ImageName, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count())
            .Select(g => new ChartItem(g.Key, g.Count(), g.Key)));

        _alerts.BeginUpdate();
        _alerts.Items.Clear();
        foreach (var a in r.Alerts.Take(50))
        {
            var item = new ListViewItem(new[] { a.LevelText, a.Rule, a.Process?.Label ?? "-", Ui.Time(a.Time), a.Detail })
            {
                Tag = a,
                ForeColor = Alert.LevelColor(a.Level),
            };
            _alerts.Items.Add(item);
        }
        _alerts.EndUpdate();
    }

    private static string HostSuffix(IEnumerable<NetConnection> g)
    {
        var host = g.Select(c => c.Outbound ? c.DestHostname : c.Event.Get("SourceHostname"))
            .FirstOrDefault(h => !string.IsNullOrEmpty(h) && h != "-");
        return host == null ? "" : $"  ({host})";
    }

    private static string PortName(int port) => port switch
    {
        20 or 21 => " ftp", 22 => " ssh", 23 => " telnet", 25 => " smtp", 53 => " dns", 67 or 68 => " dhcp",
        80 => " http", 88 => " kerberos", 110 => " pop3", 123 => " ntp", 135 => " rpc", 137 => " netbios-ns",
        138 => " netbios-dgm", 139 => " netbios-ssn", 143 => " imap", 389 => " ldap", 443 => " https", 445 => " smb",
        1900 => " ssdp", 3389 => " rdp", 5355 => " llmnr", 5985 or 5986 => " winrm", 8080 => " http-alt", 546 or 547 => " dhcpv6",
        _ => "",
    };
}
