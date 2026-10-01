using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>규칙 기반 탐지 결과 목록.</summary>
public sealed class AlertsView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;
    private readonly ListView _list = Ui.NewListView(("위험도", 60), ("시각(UTC)", 175), ("규칙", 230), ("프로세스", 150), ("부모", 130), ("내용", 700));
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.None, BackColor = Color.White };
    private readonly ComboBox _level = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly ComboBox _rule = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280 };
    private readonly Label _count = new() { AutoSize = true, ForeColor = Ui.Muted, Padding = new Padding(8, 6, 0, 0) };

    public AlertsView(INavigator nav)
    {
        _nav = nav;
        Dock = DockStyle.Fill;
        BackColor = Ui.Background;
        _level.Items.AddRange(new object[] { "전체 위험도", "높음 이상", "중간 이상" });
        _level.SelectedIndex = 0;

        var toTree = new Button { Text = "프로세스 트리", AutoSize = true };
        var toTrack = new Button { Text = "프로세스 추적", AutoSize = true };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Ui.Surface };
        bar.Controls.AddRange(new Control[] { _level, _rule, toTree, toTrack, _count,
            new Label { Text = "※ 간이 규칙 기반 탐지이므로 오탐/미탐이 있을 수 있습니다.", AutoSize = true, ForeColor = Ui.Muted, Padding = new Padding(12, 6, 0, 0) } });

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        split.Panel1.Controls.Add(_list);
        split.Panel2.Controls.Add(_detail);
        Controls.Add(split);
        Controls.Add(bar);
        Ui.SplitOnShow(split, 0.6);
        Ui.EnableSorting(_list);

        _level.SelectedIndexChanged += (_, _) => Fill();
        _rule.SelectedIndexChanged += (_, _) => Fill();
        _list.SelectedIndexChanged += (_, _) =>
        {
            if (Current is not { } a) return;
            var head = $"[{a.LevelText}] {a.Rule}\r\n{a.Detail}\r\n";
            if (a.Process is { } p)
                head += $"프로세스 경로: {string.Join(" → ", p.Ancestors().Reverse().Select(x => x.Label).Append(p.Label))}\r\n";
            _detail.Text = head + "\r\n" + EventFormat.Details(a.Event);
        };
        _list.DoubleClick += (_, _) => { if (Current?.Process is { } p) _nav.ShowProcessTree(p); };
        toTree.Click += (_, _) => { if (Current?.Process is { } p) _nav.ShowProcessTree(p); };
        toTrack.Click += (_, _) => { if (Current?.Process is { } p) _nav.ShowProcessTrack(p); };
    }

    private Alert? Current => _list.SelectedItems.Count > 0 ? _list.SelectedItems[0].Tag as Alert : null;

    public void Bind(AnalysisResult r)
    {
        _r = r;
        _rule.Items.Clear();
        _rule.Items.Add("전체 규칙");
        foreach (var g in r.Alerts.GroupBy(a => a.Rule).OrderByDescending(g => g.Count()))
            _rule.Items.Add($"{g.Key} ({g.Count()})");
        _rule.SelectedIndex = 0;
        Fill();
    }

    private void Fill()
    {
        var min = _level.SelectedIndex switch { 1 => AlertLevel.High, 2 => AlertLevel.Medium, _ => AlertLevel.Low };
        var rule = _rule.SelectedIndex > 0 ? _rule.SelectedItem!.ToString()! : null;
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var a in _r.Alerts)
        {
            if (a.Level < min) continue;
            if (rule != null && !rule.StartsWith(a.Rule + " (")) continue;
            var item = new ListViewItem(new[]
            {
                a.LevelText, Ui.Time(a.Time), a.Rule, a.Process?.Label ?? "-",
                a.Process?.Parent?.Name ?? SysmonEvent.FileName(a.Process?.ParentImage ?? ""), a.Detail,
            }) { Tag = a, ForeColor = Alert.LevelColor(a.Level) };
            _list.Items.Add(item);
        }
        _list.EndUpdate();
        _count.Text = $"{_list.Items.Count:N0}건";
    }
}
