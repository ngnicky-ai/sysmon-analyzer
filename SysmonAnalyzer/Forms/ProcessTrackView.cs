using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>
/// 프로세스별 시각화 추적 (SysmonView Process View 벤치마크).
/// 실행 파일 목록 → 실행 세션(GUID) 목록 → 선택 세션의 이벤트 흐름 다이어그램.
/// </summary>
public sealed class ProcessTrackView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;
    private List<IGrouping<string, ProcessInfo>> _images = new();

    private readonly TextBox _filter = new() { PlaceholderText = "실행 파일 필터", Dock = DockStyle.Top };
    private readonly ListView _imageList = Ui.NewListView(("실행 파일", 150), ("세션", 50), ("이벤트", 60), ("경고", 45), ("경로", 300));
    private readonly ListView _sessions = Ui.NewListView(("시작(UTC)", 175), ("PID", 55), ("이벤트", 55), ("부모", 110), ("명령줄", 400));
    private readonly ProcessTimeline _timeline = new() { Dock = DockStyle.Fill };
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.None, BackColor = Color.White };
    private readonly CheckBox _group = new() { Text = "연속 동일 이벤트 묶기", Checked = true, AutoSize = true };
    private readonly Dictionary<EventCategory, CheckBox> _cats = new();
    private readonly Label _stat = new() { AutoSize = true, ForeColor = Ui.Muted, Padding = new Padding(8, 6, 0, 0) };

    public ProcessTrackView(INavigator nav)
    {
        _nav = nav;
        Dock = DockStyle.Fill;
        BackColor = Ui.Background;

        // 왼쪽: 실행 파일 목록 / 세션 목록
        var imgPanel = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Surface };
        imgPanel.Controls.Add(_imageList);
        imgPanel.Controls.Add(_filter);
        imgPanel.Controls.Add(Ui.SectionTitle("① 실행 파일 (Image)"));
        var sesPanel = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Surface };
        sesPanel.Controls.Add(_sessions);
        sesPanel.Controls.Add(Ui.SectionTitle("② 실행 세션 (ProcessGuid)"));
        var leftSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        leftSplit.Panel1.Controls.Add(imgPanel);
        leftSplit.Panel2.Controls.Add(sesPanel);

        // 오른쪽: 필터 바 + 타임라인 + 상세
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Ui.Surface, WrapContents = true };
        bar.Controls.Add(new Label { Text = "③ 이벤트 흐름", AutoSize = true, Font = new Font(Ui.FontName, 9.5f, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) });
        foreach (var c in Enum.GetValues<EventCategory>())
        {
            var cb = new CheckBox { Text = EventCatalog.CategoryName(c), Checked = true, AutoSize = true };
            cb.CheckedChanged += (_, _) => ApplyTimelineFilter();
            _cats[c] = cb;
            bar.Controls.Add(cb);
        }
        bar.Controls.Add(_group);
        var toTree = new Button { Text = "트리에서 보기", AutoSize = true };
        var parentBtn = new Button { Text = "◀ 부모", AutoSize = true };
        bar.Controls.Add(parentBtn);
        bar.Controls.Add(toTree);
        bar.Controls.Add(_stat);
        _group.CheckedChanged += (_, _) => ApplyTimelineFilter();

        var rightSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        rightSplit.Panel1.Controls.Add(_timeline);
        rightSplit.Panel2.Controls.Add(_detail);
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(rightSplit);
        right.Controls.Add(bar);

        var main = new SplitContainer { Dock = DockStyle.Fill };
        main.Panel1.Controls.Add(leftSplit);
        main.Panel2.Controls.Add(right);
        Controls.Add(main);
        Ui.SplitOnShow(main, 0.36);
        Ui.SplitOnShow(leftSplit, 0.5);
        Ui.SplitOnShow(rightSplit, 0.72);

        Ui.EnableSorting(_imageList);
        Ui.EnableSorting(_sessions);
        _filter.TextChanged += (_, _) => FillImages();
        _imageList.SelectedIndexChanged += (_, _) =>
        {
            if (!_suppress && _imageList.SelectedItems.Count > 0) FillSessions((IGrouping<string, ProcessInfo>)_imageList.SelectedItems[0].Tag!);
        };
        _sessions.SelectedIndexChanged += (_, _) =>
        {
            if (!_suppress && _sessions.SelectedItems.Count > 0) ShowSession((ProcessInfo)_sessions.SelectedItems[0].Tag!);
        };
        _sessions.DoubleClick += (_, _) =>
        {
            if (_sessions.SelectedItems.Count > 0) _nav.ShowProcessTree((ProcessInfo)_sessions.SelectedItems[0].Tag!);
        };
        _timeline.EventSelected += (_, e) => _detail.Text = EventFormat.Details(e);
        _timeline.ProcessActivated += (_, p) => ShowProcess(p);
        toTree.Click += (_, _) => { if (_timeline.Process != null) _nav.ShowProcessTree(_timeline.Process); };
        parentBtn.Click += (_, _) => { if (_timeline.Process?.Parent != null) ShowProcess(_timeline.Process.Parent); };
    }

    public void Bind(AnalysisResult r)
    {
        _r = r;
        _images = r.Processes.Values
            .Where(p => p.Image.Length > 0)
            .GroupBy(p => p.Image, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => SysmonEvent.FileName(g.Key), StringComparer.OrdinalIgnoreCase)
            .ToList();
        FillImages();
        _sessions.Items.Clear();
        _timeline.ShowProcess(null);
        _detail.Clear();
    }

    private void FillImages()
    {
        var q = _filter.Text.Trim();
        _imageList.BeginUpdate();
        _imageList.Items.Clear();
        foreach (var g in _images)
        {
            if (q.Length > 0 && !g.Key.Contains(q, StringComparison.OrdinalIgnoreCase)) continue;
            int alerts = g.Sum(p => p.Alerts.Count);
            var item = new ListViewItem(new[]
            {
                SysmonEvent.FileName(g.Key), g.Count().ToString(), g.Sum(p => p.Events.Count).ToString(),
                alerts > 0 ? alerts.ToString() : "", g.Key,
            }) { Tag = g };
            if (alerts > 0) item.ForeColor = Alert.LevelColor(g.Max(p => p.MaxAlertLevel ?? AlertLevel.Low));
            _imageList.Items.Add(item);
        }
        _imageList.EndUpdate();
    }

    private void FillSessions(IGrouping<string, ProcessInfo> g)
    {
        _sessions.BeginUpdate();
        _sessions.Items.Clear();
        foreach (var p in g.OrderBy(p => p.Start ?? p.FirstSeen))
        {
            var item = new ListViewItem(new[]
            {
                Ui.Time(p.Start ?? p.FirstSeen), p.Pid.ToString(), p.Events.Count.ToString(),
                p.Parent?.Name ?? SysmonEvent.FileName(p.ParentImage), p.CommandLine,
            }) { Tag = p };
            if (p.MaxAlertLevel is { } lv) item.ForeColor = Alert.LevelColor(lv);
            else if (!p.HasCreateEvent) item.ForeColor = Ui.Muted;
            _sessions.Items.Add(item);
        }
        _sessions.EndUpdate();
        if (_sessions.Items.Count > 0) _sessions.Items[0].Selected = true;
    }

    private void ShowSession(ProcessInfo p)
    {
        _timeline.ShowProcess(p);
        _detail.Text = p.CreateEvent != null ? EventFormat.Details(p.CreateEvent) : "(프로세스 생성 이벤트 없음)";
        var byCat = p.Events.GroupBy(e => EventCatalog.Get(e.EventId).Category)
            .Select(x => $"{EventCatalog.CategoryName(x.Key)} {x.Count()}");
        _stat.Text = $"{p.Label}: {string.Join(" · ", byCat)} · 자식 {p.Children.Count}";
    }

    private void ApplyTimelineFilter()
    {
        _timeline.Categories.Clear();
        foreach (var (c, cb) in _cats) if (cb.Checked) _timeline.Categories.Add(c);
        _timeline.GroupRepeats = _group.Checked;
        _timeline.Rebuild();
    }

    /// <summary>특정 프로세스 세션으로 바로 이동.</summary>
    public void ShowProcess(ProcessInfo p)
    {
        SelectImage(p.Image);
        _suppress = true;
        foreach (ListViewItem it in _sessions.Items)
        {
            it.Selected = it.Tag == p;
            if (it.Selected) it.EnsureVisible();
        }
        _suppress = false;
        ShowSession(p);
    }

    private bool _suppress;

    public void SelectImage(string image)
    {
        if (_filter.Text.Length > 0 && !image.Contains(_filter.Text, StringComparison.OrdinalIgnoreCase))
            _filter.Text = "";
        foreach (ListViewItem it in _imageList.Items)
        {
            if (((IGrouping<string, ProcessInfo>)it.Tag!).Key.Equals(image, StringComparison.OrdinalIgnoreCase))
            {
                _suppress = true;
                it.Selected = true;
                it.Focused = true;
                _suppress = false;
                it.EnsureVisible();
                FillSessions((IGrouping<string, ProcessInfo>)it.Tag!);
                return;
            }
        }
    }
}
