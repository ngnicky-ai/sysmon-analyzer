using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>
/// 부모-자식 프로세스 계층 트리 + 관계 그래프 + 속성/이벤트.
/// SysmonView의 Hierarchy View에 해당.
/// </summary>
public sealed class ProcessTreeView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;
    private readonly Dictionary<ProcessInfo, TreeNode> _nodeMap = new();
    private List<ProcessInfo> _matches = new();
    private int _matchIndex = -1;
    private bool _syncing;

    private readonly TreeView _tree = new() { Dock = DockStyle.Fill, HideSelection = false, BorderStyle = BorderStyle.None, ShowNodeToolTips = true };
    private readonly TextBox _search = new() { PlaceholderText = "이름 / PID / 명령줄 / GUID / 해시 검색 후 Enter", Width = 280 };
    private readonly CheckBox _alertsOnly = new() { Text = "경고 프로세스 경로만", AutoSize = true };
    private readonly CheckBox _hideSystem = new() { Text = "추정(스텁) 루트 숨김", AutoSize = true };
    private readonly Label _matchLabel = new() { AutoSize = true, ForeColor = Ui.Muted };
    private readonly ProcessGraph _graph = new() { Dock = DockStyle.Fill };
    private readonly CheckBox _showNet = new() { Text = "네트워크 대상 표시", Checked = true, AutoSize = true };
    private readonly CheckBox _fullTree = new() { Text = "전체 트리 그래프", AutoSize = true };
    private readonly ListView _props = Ui.NewListView(("항목", 130), ("값", 700));
    private readonly ListView _events = Ui.NewListView(("시각(UTC)", 175), ("ID", 40), ("유형", 130), ("내용", 800));
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.None, BackColor = Color.White };

    public ProcessTreeView(INavigator nav)
    {
        _nav = nav;
        Dock = DockStyle.Fill;
        BackColor = Ui.Background;
        Ui.EnableDoubleBuffer(_tree);

        // 왼쪽: 검색 + 트리
        var searchBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), WrapContents = true, BackColor = Ui.Surface };
        var nextBtn = new Button { Text = "다음", AutoSize = true };
        var expandBtn = new Button { Text = "모두 펼치기", AutoSize = true };
        var collapseBtn = new Button { Text = "접기", AutoSize = true };
        searchBar.Controls.AddRange(new Control[] { _search, nextBtn, _matchLabel, _alertsOnly, _hideSystem, expandBtn, collapseBtn });
        var left = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Surface };
        left.Controls.Add(_tree);
        left.Controls.Add(searchBar);

        // 오른쪽 위: 그래프
        var graphBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Ui.Surface };
        var zoomIn = new Button { Text = "확대 +", AutoSize = true };
        var zoomOut = new Button { Text = "축소 −", AutoSize = true };
        var fit = new Button { Text = "화면 맞춤", AutoSize = true };
        var center = new Button { Text = "선택 위치로", AutoSize = true };
        var save = new Button { Text = "PNG 저장", AutoSize = true };
        var track = new Button { Text = "프로세스 추적 ▶", AutoSize = true };
        graphBar.Controls.AddRange(new Control[] { new Label { Text = "관계 그래프", AutoSize = true, Font = new Font(Ui.FontName, 9.5f, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) },
            _showNet, _fullTree, zoomIn, zoomOut, fit, center, save, track });
        var graphPanel = new Panel { Dock = DockStyle.Fill };
        graphPanel.Controls.Add(_graph);
        graphPanel.Controls.Add(graphBar);

        // 오른쪽 아래: 속성 / 이벤트 / 상세
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var tp1 = new TabPage("프로세스 속성");
        tp1.Controls.Add(_props);
        var evSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        evSplit.Panel1.Controls.Add(_events);
        evSplit.Panel2.Controls.Add(_detail);
        var tp2 = new TabPage("이벤트");
        tp2.Controls.Add(evSplit);
        tabs.TabPages.AddRange(new[] { tp1, tp2 });

        var rightSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        rightSplit.Panel1.Controls.Add(graphPanel);
        rightSplit.Panel2.Controls.Add(tabs);

        var main = new SplitContainer { Dock = DockStyle.Fill };
        main.Panel1.Controls.Add(left);
        main.Panel2.Controls.Add(rightSplit);
        Controls.Add(main);

        Ui.SplitOnShow(main, 0.28);
        Ui.SplitOnShow(rightSplit, 0.6);
        Ui.SplitOnShow(evSplit, 0.55);

        _tree.AfterSelect += (_, e) =>
        {
            if (_syncing || e.Node?.Tag is not ProcessInfo p) return;
            ShowSelected(p, refocusGraph: true);
        };
        _tree.NodeMouseDoubleClick += (_, e) => { if (e.Node.Tag is ProcessInfo p) _nav.ShowProcessTrack(p); };
        _search.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Search(); } };
        nextBtn.Click += (_, _) => Search();
        _alertsOnly.CheckedChanged += (_, _) => BuildTree();
        _hideSystem.CheckedChanged += (_, _) => BuildTree();
        expandBtn.Click += (_, _) => { _tree.BeginUpdate(); _tree.ExpandAll(); _tree.EndUpdate(); _tree.SelectedNode?.EnsureVisible(); };
        collapseBtn.Click += (_, _) =>
        {
            _tree.BeginUpdate();
            _tree.CollapseAll();
            foreach (TreeNode n in _tree.Nodes) n.Expand();
            _tree.EndUpdate();
        };

        _showNet.CheckedChanged += (_, _) => { _graph.ShowNetwork = _showNet.Checked; RefreshGraph(); };
        _fullTree.CheckedChanged += (_, _) => { _graph.FullTree = _fullTree.Checked; RefreshGraph(); };
        zoomIn.Click += (_, _) => _graph.ZoomBy(1.2f);
        zoomOut.Click += (_, _) => _graph.ZoomBy(1 / 1.2f);
        fit.Click += (_, _) => _graph.FitToView();
        center.Click += (_, _) => { if (_graph.SelectedProcess != null) _graph.CenterOn(_graph.SelectedProcess); };
        save.Click += (_, _) => SaveGraph();
        track.Click += (_, _) => { if (Selected != null) _nav.ShowProcessTrack(Selected); };
        _graph.ProcessClicked += (_, p) => SelectInTree(p, refocusGraph: false);
        _graph.ProcessActivated += (_, p) => SelectInTree(p, refocusGraph: true);

        _events.SelectedIndexChanged += (_, _) =>
        {
            if (_events.SelectedItems.Count > 0) _detail.Text = EventFormat.Details(_events.SelectedItems[0].Tag as SysmonEvent);
        };
        _events.DoubleClick += (_, _) =>
        {
            if (_events.SelectedItems.Count > 0 && _events.SelectedItems[0].Tag is SysmonEvent ev &&
                ev.EventId == 1 && _r.Processes.TryGetValue(ev.ProcessGuid, out var child) && child != Selected)
                SelectInTree(child, true);
        };
    }

    public ProcessInfo? Selected => _tree.SelectedNode?.Tag as ProcessInfo;

    public void Bind(AnalysisResult r)
    {
        _r = r;
        _matches.Clear();
        _matchIndex = -1;
        _matchLabel.Text = "";
        BuildTree();
        _graph.ShowProcess(null, Array.Empty<ProcessInfo>());
        _props.Items.Clear();
        _events.Items.Clear();
        _detail.Clear();
    }

    private void BuildTree()
    {
        var prevSelected = Selected;
        _tree.BeginUpdate();
        _tree.Nodes.Clear();
        _nodeMap.Clear();

        HashSet<ProcessInfo>? keep = null;
        if (_alertsOnly.Checked)
        {
            keep = new HashSet<ProcessInfo>();
            foreach (var p in _r.Processes.Values.Where(p => p.Alerts.Count > 0))
            {
                keep.Add(p);
                foreach (var a in p.Ancestors()) keep.Add(a);
            }
        }

        foreach (var root in _r.Roots)
        {
            if (keep != null && !keep.Contains(root)) continue;
            if (_hideSystem.Checked && !root.HasCreateEvent && root.Children.Count == 0) continue;
            _tree.Nodes.Add(CreateNode(root, keep, 0));
        }
        foreach (TreeNode n in _tree.Nodes) n.Expand();
        if (keep != null) _tree.ExpandAll();
        _tree.EndUpdate();

        if (prevSelected != null && _nodeMap.ContainsKey(prevSelected)) SelectInTree(prevSelected, false);
    }

    private TreeNode CreateNode(ProcessInfo p, HashSet<ProcessInfo>? keep, int depth)
    {
        var level = p.MaxAlertLevel;
        var text = $"{p.Name} ({p.Pid})";
        if (p.Children.Count > 0) text += $"  [{p.Children.Count}]";
        if (level.HasValue) text = "⚠ " + text;
        var node = new TreeNode(text)
        {
            Tag = p,
            ToolTipText = $"{p.Image}\n{p.CommandLine}\n시작: {Ui.Time(p.Start ?? p.FirstSeen)}  종료: {Ui.Time(p.End)}",
        };
        if (level.HasValue) node.ForeColor = Alert.LevelColor(level.Value);
        else if (!p.HasCreateEvent) node.ForeColor = Ui.Muted;
        _nodeMap[p] = node;
        if (depth < 300)
            foreach (var c in p.Children)
                if (keep == null || keep.Contains(c))
                    node.Nodes.Add(CreateNode(c, keep, depth + 1));
        return node;
    }

    public void SelectInTree(ProcessInfo p, bool refocusGraph)
    {
        if (!_nodeMap.TryGetValue(p, out var node))
        {
            // 필터로 숨겨진 경우 필터 해제 후 다시 시도
            if (_alertsOnly.Checked || _hideSystem.Checked)
            {
                _alertsOnly.Checked = false;
                _hideSystem.Checked = false;
            }
            if (!_nodeMap.TryGetValue(p, out node)) return;
        }
        _syncing = true;
        _tree.SelectedNode = node;
        node.EnsureVisible();
        _syncing = false;
        ShowSelected(p, refocusGraph);
    }

    private void ShowSelected(ProcessInfo p, bool refocusGraph)
    {
        if (refocusGraph) _graph.ShowProcess(p, _r.Roots);
        else _graph.Select(p);
        FillProps(p);
        FillEvents(p);
    }

    private void RefreshGraph()
    {
        var sel = Selected;
        _graph.ShowProcess(sel, _r.Roots);
    }

    private void FillProps(ProcessInfo p)
    {
        _props.BeginUpdate();
        _props.Items.Clear();
        void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) _props.Items.Add(new ListViewItem(new[] { k, v })); }
        Add("이미지", p.Image);
        Add("PID", p.Pid.ToString());
        Add("ProcessGuid", p.Guid);
        Add("명령줄", p.CommandLine);
        Add("작업 디렉터리", p.CurrentDirectory);
        Add("사용자", p.User);
        Add("무결성 수준", p.IntegrityLevel);
        Add("LogonId", p.LogonId);
        Add("시작(UTC)", Ui.Time(p.Start));
        Add("종료(UTC)", Ui.Time(p.End));
        Add("최초/최종 관측", $"{Ui.Time(p.FirstSeen)} ~ {Ui.Time(p.LastSeen == DateTime.MinValue ? null : p.LastSeen)}");
        Add("해시", p.Hashes);
        Add("원본 파일명", p.OriginalFileName);
        Add("설명", p.Description);
        Add("제품", p.Product);
        Add("회사", p.Company);
        Add("파일 버전", p.FileVersion);
        Add("부모", p.Parent != null ? $"{p.Parent.Name} (PID {p.Parent.Pid})" : SysmonEvent.FileName(p.ParentImage));
        Add("부모 명령줄", p.ParentCommandLine);
        Add("조상 경로", string.Join(" → ", p.Ancestors().Reverse().Select(a => a.Name).Append(p.Name)));
        Add("자식 / 자손", $"{p.Children.Count} / {p.Descendants().Count()}");
        Add("이벤트 수", string.Join(", ", p.Events.GroupBy(e => e.EventId).OrderBy(g => g.Key).Select(g => $"[{g.Key}] {g.Count()}")));
        Add("컴퓨터", p.Computer);
        if (!p.HasCreateEvent) Add("비고", "프로세스 생성(1) 이벤트가 없어 다른 이벤트/자식 정보로 추정한 프로세스입니다.");
        foreach (var a in p.Alerts)
        {
            var item = new ListViewItem(new[] { $"⚠ 경고({a.LevelText})", $"{a.Rule}: {a.Detail}" }) { ForeColor = Alert.LevelColor(a.Level) };
            _props.Items.Add(item);
        }
        _props.EndUpdate();
    }

    private void FillEvents(ProcessInfo p)
    {
        _events.BeginUpdate();
        _events.Items.Clear();
        var list = p.Events.Concat(p.Children.Where(c => c.CreateEvent != null).Select(c => c.CreateEvent!))
            .Concat(p.IncomingEvents).Distinct().OrderBy(e => e.Time).ThenBy(e => e.Index).Take(5000);
        foreach (var e in list)
        {
            var info = EventCatalog.Get(e.EventId);
            string type = info.Korean;
            if (e.EventId == 1 && e.ProcessGuid != p.Guid) type = "자식 프로세스 생성";
            if (e.EventId is 8 or 10 && e.TargetProcessGuid == p.Guid) type += " (대상)";
            var item = new ListViewItem(new[] { Ui.Time(e.Time), e.EventId.ToString(), type, e.Summary }) { Tag = e };
            item.UseItemStyleForSubItems = false;
            item.SubItems[2].ForeColor = info.Color;
            _events.Items.Add(item);
        }
        _events.EndUpdate();
        _detail.Clear();
    }

    private void Search()
    {
        var q = _search.Text.Trim();
        if (q.Length == 0) return;
        if (_matches.Count == 0 || (string)(_search.Tag ?? "") != q)
        {
            _search.Tag = q;
            _matches = _r.Processes.Values
                .Where(p => Matches(p, q))
                .OrderBy(p => p.FirstSeen).ToList();
            _matchIndex = -1;
        }
        if (_matches.Count == 0)
        {
            _matchLabel.Text = "결과 없음";
            return;
        }
        _matchIndex = (_matchIndex + 1) % _matches.Count;
        _matchLabel.Text = $"{_matchIndex + 1}/{_matches.Count}";
        SelectInTree(_matches[_matchIndex], true);
    }

    private static bool Matches(ProcessInfo p, string q)
    {
        if (int.TryParse(q, out var pid) && p.Pid == pid) return true;
        var c = StringComparison.OrdinalIgnoreCase;
        return p.Image.Contains(q, c) || p.CommandLine.Contains(q, c) || p.Guid.Contains(q, c) ||
               p.Hashes.Contains(q, c) || p.User.Contains(q, c);
    }

    public void SetSearch(string text)
    {
        _search.Text = text;
        _matches.Clear();
        Search();
    }

    private void SaveGraph()
    {
        using var dlg = new SaveFileDialog { Filter = "PNG 이미지|*.png", FileName = $"process_graph_{Selected?.Name ?? "all"}.png" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        _graph.SaveImage(dlg.FileName);
    }

    /// <summary>스냅샷 모드용.</summary>
    internal ProcessGraph Graph => _graph;
}
