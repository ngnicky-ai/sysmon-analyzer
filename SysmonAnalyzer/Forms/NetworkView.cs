using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>네트워크 연결 분석: 프로세스·원격 IP·포트별 집계 + 원본 연결 목록.</summary>
public sealed class NetworkView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;
    private List<NetConnection> _filtered = new();
    private List<NetConnection> _raw = new();

    private readonly TextBox _filter = new() { PlaceholderText = "IP / 포트(:443) / 프로세스 / 호스트명 필터", Width = 320 };
    private readonly CheckBox _publicOnly = new() { Text = "공인 IP만", AutoSize = true };
    private readonly ComboBox _dir = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
    private readonly ComboBox _groupBy = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
    private readonly Label _count = new() { AutoSize = true, ForeColor = Ui.Muted, Padding = new Padding(8, 6, 0, 0) };
    private readonly ListView _agg = Ui.NewListView(("키", 330), ("연결 수", 70), ("프로세스", 200), ("공인", 45), ("호스트명", 200), ("최초(UTC)", 175), ("최종(UTC)", 175));
    private readonly ListView _list = Ui.NewListView(("시각(UTC)", 175), ("프로세스", 130), ("PID", 55), ("방향", 75), ("프로토콜", 60), ("로컬", 200), ("원격", 220), ("원격 호스트", 200), ("포트명", 80));

    public NetworkView(INavigator nav)
    {
        _nav = nav;
        Dock = DockStyle.Fill;
        BackColor = Ui.Background;

        _dir.Items.AddRange(new object[] { "전체 방향", "아웃바운드", "인바운드" });
        _dir.SelectedIndex = 0;
        _groupBy.Items.AddRange(new object[] { "프로세스 + 원격 IP:Port", "원격 IP", "원격 IP:Port", "서비스 포트", "프로세스" });
        _groupBy.SelectedIndex = 0;

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Ui.Surface };
        bar.Controls.AddRange(new Control[]
        {
            _filter, _publicOnly, _dir,
            new Label { Text = "집계 기준", AutoSize = true, Padding = new Padding(8, 6, 0, 0) }, _groupBy, _count,
        });

        _list.VirtualMode = true;
        _list.RetrieveVirtualItem += (_, e) => e.Item = MakeRow(_raw[e.ItemIndex]);

        var aggPanel = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Surface };
        aggPanel.Controls.Add(_agg);
        aggPanel.Controls.Add(Ui.SectionTitle("연결 집계 · 선택 시 아래 목록 필터 · 더블클릭: 프로세스 추적"));
        var listPanel = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Surface };
        listPanel.Controls.Add(_list);
        listPanel.Controls.Add(Ui.SectionTitle("연결 이벤트 목록 · 더블클릭: 프로세스 추적"));
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        split.Panel1.Controls.Add(aggPanel);
        split.Panel2.Controls.Add(listPanel);
        Controls.Add(split);
        Controls.Add(bar);
        Ui.SplitOnShow(split, 0.5);
        Ui.EnableSorting(_agg);

        var timer = new System.Windows.Forms.Timer { Interval = 300 };
        timer.Tick += (_, _) => { timer.Stop(); Apply(); };
        _filter.TextChanged += (_, _) => { timer.Stop(); timer.Start(); };
        _publicOnly.CheckedChanged += (_, _) => Apply();
        _dir.SelectedIndexChanged += (_, _) => Apply();
        _groupBy.SelectedIndexChanged += (_, _) => Apply();
        _agg.SelectedIndexChanged += (_, _) => FillRaw();
        _agg.DoubleClick += (_, _) =>
        {
            if (_agg.SelectedItems.Count > 0 && _agg.SelectedItems[0].Tag is List<NetConnection> g && g[0].Process is { } p)
                _nav.ShowProcessTrack(p);
        };
        _list.DoubleClick += (_, _) =>
        {
            if (_list.SelectedIndices.Count > 0 && _raw[_list.SelectedIndices[0]].Process is { } p)
                _nav.ShowProcessTrack(p);
        };
    }

    public void Bind(AnalysisResult r)
    {
        _r = r;
        Apply();
    }

    public void SetFilter(string? text)
    {
        _publicOnly.Checked = false;
        _dir.SelectedIndex = 0;
        _filter.Text = text ?? "";
        Apply();
    }

    private bool Match(NetConnection c, string q)
    {
        if (q.Length == 0) return true;
        if (q.StartsWith(':') && int.TryParse(q[1..], out var port))
            return c.ServicePort == port || c.RemotePort == port || c.LocalPort == port;
        var ci = StringComparison.OrdinalIgnoreCase;
        return c.RemoteIp.Contains(q, ci) || c.LocalIp.Contains(q, ci) || c.RemoteEndpoint.Contains(q, ci) ||
               c.Image.Contains(q, ci) || c.DestHostname.Contains(q, ci) || c.Protocol.Equals(q, ci);
    }

    private void Apply()
    {
        var q = _filter.Text.Trim();
        _filtered = _r.Connections.Where(c =>
            Match(c, q) &&
            (!_publicOnly.Checked || IpUtil.IsPublic(c.RemoteIp)) &&
            (_dir.SelectedIndex == 0 || (_dir.SelectedIndex == 1) == c.Outbound)).ToList();

        Func<NetConnection, string> key = _groupBy.SelectedIndex switch
        {
            1 => c => c.RemoteIp,
            2 => c => $"{c.RemoteEndpoint} {c.Protocol}",
            3 => c => $"{c.ServicePort}/{c.Protocol} ({c.Direction})",
            4 => c => c.ImageName,
            _ => c => $"{c.ImageName}  {(c.Outbound ? "→" : "⇠")}  {c.RemoteEndpoint} {c.Protocol}",
        };

        _agg.BeginUpdate();
        _agg.Items.Clear();
        foreach (var g in _filtered.GroupBy(key).OrderByDescending(g => g.Count()))
        {
            var list = g.ToList();
            var procs = list.Select(c => c.ImageName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var host = list.Select(c => c.Outbound ? c.DestHostname : c.Event.Get("SourceHostname"))
                .FirstOrDefault(h => !string.IsNullOrEmpty(h) && h != "-") ?? "";
            bool pub = list.Any(c => IpUtil.IsPublic(c.RemoteIp));
            var item = new ListViewItem(new[]
            {
                g.Key, list.Count.ToString("N0"),
                procs.Count <= 3 ? string.Join(", ", procs) : $"{string.Join(", ", procs.Take(3))} 외 {procs.Count - 3}",
                pub ? "●" : "", host, Ui.Time(list[0].Time), Ui.Time(list[^1].Time),
            }) { Tag = list };
            if (pub) item.ForeColor = Color.FromArgb(180, 30, 40);
            if (list.Any(c => c.Process?.Alerts.Count > 0)) item.BackColor = Color.FromArgb(255, 244, 240);
            _agg.Items.Add(item);
        }
        _agg.EndUpdate();
        _count.Text = $"연결 {_filtered.Count:N0}건 / 전체 {_r.Connections.Count:N0}건 · 그룹 {_agg.Items.Count:N0}개";
        FillRaw();
    }

    private void FillRaw()
    {
        _raw = _agg.SelectedItems.Count > 0 && _agg.SelectedItems[0].Tag is List<NetConnection> sel ? sel : _filtered;
        _list.VirtualListSize = 0;
        _list.VirtualListSize = _raw.Count;
        _list.Invalidate();
    }

    private static ListViewItem MakeRow(NetConnection c)
    {
        var item = new ListViewItem(new[]
        {
            Ui.Time(c.Time), c.ImageName, c.Event.ProcessId.ToString(), c.Direction, c.Protocol,
            IpUtil.Endpoint(c.LocalIp, c.LocalPort), c.RemoteEndpoint,
            c.Outbound ? c.DestHostname : c.Event.Get("SourceHostname"), c.DestPortName,
        });
        if (IpUtil.IsPublic(c.RemoteIp)) item.ForeColor = Color.FromArgb(180, 30, 40);
        return item;
    }
}
