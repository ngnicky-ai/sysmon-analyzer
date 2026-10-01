using System.Diagnostics;
using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;
using SysmonAnalyzer.Parsing;

namespace SysmonAnalyzer.Forms;

public sealed class MainForm : Form, INavigator
{
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill, Padding = new Point(14, 5) };
    private readonly TabPage _tpDash = new("대시보드");
    private readonly TabPage _tpTree = new("프로세스 트리");
    private readonly TabPage _tpTrack = new("프로세스 추적");
    private readonly TabPage _tpNet = new("네트워크");
    private readonly TabPage _tpAlerts = new("탐지 결과");
    private readonly TabPage _tpEvents = new("전체 이벤트");

    private readonly DashboardView _dash;
    private readonly ProcessTreeView _tree;
    private readonly ProcessTrackView _track;
    private readonly NetworkView _net;
    private readonly AlertsView _alerts;
    private readonly EventsView _events;

    private readonly ToolStripStatusLabel _status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripProgressBar _progress = new() { Style = ProgressBarStyle.Marquee, Visible = false, Width = 160 };
    private readonly Panel _welcome;

    private readonly List<SysmonEvent> _loaded = new();
    private readonly List<string> _sources = new();
    private CancellationTokenSource? _cts;
    private bool _busy;

    public AnalysisResult Result { get; private set; } = AnalysisResult.Empty;

    public MainForm()
    {
        Text = "Sysmon Analyzer";
        Font = new Font(Ui.FontName, 9f);
        BackColor = Ui.Background;
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(Ui.S(this, 1500), Ui.S(this, 950));
        MinimumSize = new Size(Ui.S(this, 900), Ui.S(this, 600));
        AllowDrop = true;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        _dash = new DashboardView(this);
        _tree = new ProcessTreeView(this);
        _track = new ProcessTrackView(this);
        _net = new NetworkView(this);
        _alerts = new AlertsView(this);
        _events = new EventsView(this);
        _tpDash.Controls.Add(_dash);
        _tpTree.Controls.Add(_tree);
        _tpTrack.Controls.Add(_track);
        _tpNet.Controls.Add(_net);
        _tpAlerts.Controls.Add(_alerts);
        _tpEvents.Controls.Add(_events);
        _tabs.TabPages.AddRange(new[] { _tpDash, _tpTree, _tpTrack, _tpNet, _tpAlerts, _tpEvents });

        _welcome = BuildWelcome();

        var menu = BuildMenu();
        var statusStrip = new StatusStrip();
        statusStrip.Items.AddRange(new ToolStripItem[] { _status, _progress });
        _status.Text = "EVTX 파일을 열거나 창에 끌어다 놓으세요.";

        Controls.Add(_tabs);
        Controls.Add(_welcome);
        Controls.Add(menu);
        Controls.Add(statusStrip);
        MainMenuStrip = menu;
        _tabs.Visible = false;

        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files)
                await LoadFilesAsync(files, append: ModifierKeys.HasFlag(Keys.Control));
        };
        FormClosing += (_, _) => _cts?.Cancel();

        // Ctrl+마우스 휠 = 화면 확대/축소 (어느 컨트롤 위에서든)
        var wheel = new Ui.CtrlWheelFilter(this, step => ZoomStep(step));
        Application.AddMessageFilter(wheel);
        FormClosed += (_, _) => Application.RemoveMessageFilter(wheel);
        Load += (_, _) =>
        {
            if (ApplySavedZoom && LoadSavedZoom() is { } z) SetZoom(z, save: false);
        };
    }

    // ---- 화면 확대/축소 ----
    private const float ZoomStepSize = 0.1f;

    /// <summary>시작 시 저장된 확대 배율을 적용할지 (스냅샷 모드에서는 끔).</summary>
    public bool ApplySavedZoom { get; set; } = true;

    private static string SettingsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SysmonAnalyzer", "settings.ini");

    public void ZoomStep(int direction)
    {
        if (direction == 0) SetZoom(1f);
        else SetZoom(Ui.Zoom + direction * ZoomStepSize);
    }

    public void SetZoom(float zoom, bool save = true)
    {
        Ui.SetZoom(this, zoom);
        _status.Text = $"화면 배율 {Ui.Zoom * 100:0}%  (Ctrl+휠 / Ctrl + + - 0)";
        if (save) SaveZoom();
    }

    private static float? LoadSavedZoom()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return null;
            foreach (var line in File.ReadAllLines(SettingsPath))
                if (line.StartsWith("zoom=") &&
                    float.TryParse(line[5..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var z))
                    return z;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return null;
    }

    private static void SaveZoom()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, $"zoom={Ui.Zoom.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n");
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        switch (keyData)
        {
            case Keys.Control | Keys.Oemplus:
            case Keys.Control | Keys.Shift | Keys.Oemplus:
            case Keys.Control | Keys.Add:
                ZoomStep(+1);
                return true;
            case Keys.Control | Keys.OemMinus:
            case Keys.Control | Keys.Subtract:
                ZoomStep(-1);
                return true;
            case Keys.Control | Keys.D0:
            case Keys.Control | Keys.NumPad0:
                ZoomStep(0);
                return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    private MenuStrip BuildMenu()
    {
        var menu = new MenuStrip();
        var file = new ToolStripMenuItem("파일(&F)");
        file.DropDownItems.Add(new ToolStripMenuItem("EVTX/XML 열기(&O)...", null, async (_, _) => await OpenDialog(false), Keys.Control | Keys.O));
        file.DropDownItems.Add(new ToolStripMenuItem("파일 추가(병합)(&A)...", null, async (_, _) => await OpenDialog(true), Keys.Control | Keys.Shift | Keys.O));
        file.DropDownItems.Add(new ToolStripMenuItem("로컬 Sysmon 로그 불러오기(&L)", null, async (_, _) => await LoadLocalAsync()));
        file.DropDownItems.Add(new ToolStripSeparator());
        file.DropDownItems.Add(new ToolStripMenuItem("현재 이벤트 목록 CSV 내보내기(&E)...", null, (_, _) => ExportCsv()));
        file.DropDownItems.Add(new ToolStripMenuItem("분석 요약 보고서(HTML) 내보내기(&R)...", null, (_, _) => ExportReport()));
        file.DropDownItems.Add(new ToolStripSeparator());
        file.DropDownItems.Add(new ToolStripMenuItem("닫기(&C)", null, (_, _) => { _loaded.Clear(); _sources.Clear(); Bind(AnalysisResult.Empty); }));
        file.DropDownItems.Add(new ToolStripMenuItem("종료(&X)", null, (_, _) => Close()));

        var view = new ToolStripMenuItem("보기(&V)");
        void AddTab(string text, TabPage page, Keys key) =>
            view.DropDownItems.Add(new ToolStripMenuItem(text, null, (_, _) => { if (_tabs.Visible) _tabs.SelectedTab = page; }, key));
        AddTab("대시보드", _tpDash, Keys.F2);
        AddTab("프로세스 트리", _tpTree, Keys.F3);
        AddTab("프로세스 추적", _tpTrack, Keys.F4);
        AddTab("네트워크", _tpNet, Keys.F5);
        AddTab("탐지 결과", _tpAlerts, Keys.F6);
        AddTab("전체 이벤트", _tpEvents, Keys.F7);
        view.DropDownItems.Add(new ToolStripSeparator());
        view.DropDownItems.Add(new ToolStripMenuItem("크게 보기", null, (_, _) => ZoomStep(+1)) { ShortcutKeyDisplayString = "Ctrl++ / Ctrl+휠↑" });
        view.DropDownItems.Add(new ToolStripMenuItem("작게 보기", null, (_, _) => ZoomStep(-1)) { ShortcutKeyDisplayString = "Ctrl+- / Ctrl+휠↓" });
        view.DropDownItems.Add(new ToolStripMenuItem("기본 크기(100%)", null, (_, _) => ZoomStep(0)) { ShortcutKeyDisplayString = "Ctrl+0" });

        var help = new ToolStripMenuItem("도움말(&H)");
        help.DropDownItems.Add(new ToolStripMenuItem("사용법", null, (_, _) => MessageBox.Show(this, HelpText, "사용법")));

        menu.Items.AddRange(new ToolStripItem[] { file, view, help });
        return menu;
    }

    private const string HelpText =
        "■ 파일 열기: 파일 > EVTX/XML 열기 또는 창에 드래그 (Ctrl+드래그 = 병합)\n" +
        "   - Sysmon 로그(.evtx), wevtutil qe ... /f:xml 출력(.xml) 지원\n" +
        "   - 로컬 Sysmon 로그는 관리자 권한이 필요할 수 있습니다\n\n" +
        "■ 대시보드: 요약 통계, 차트 항목 클릭 시 해당 탭으로 드릴다운\n" +
        "■ 프로세스 트리: 부모→자식 계층, 관계 그래프(휠 확대/축소, 드래그 이동,\n" +
        "   더블클릭 이동), 네트워크 대상 노드, PNG 저장\n" +
        "■ 프로세스 추적: 실행 파일 → 세션 → 이벤트 흐름(SysmonView 스타일)\n" +
        "   자식 생성 항목 더블클릭 시 자식으로, 헤더의 부모 링크로 부모로 이동\n" +
        "■ 네트워크: 프로세스/IP/포트별 집계, ':443' 처럼 포트 필터\n" +
        "■ 탐지 결과: 간이 규칙 기반 의심 행위\n" +
        "■ 전체 이벤트: 공백=AND, -단어=제외 검색, 컬럼 클릭 정렬\n\n" +
        "■ 화면 배율: Ctrl+마우스 휠, Ctrl + + / Ctrl + - (70%~250%), Ctrl+0 = 100%\n" +
        "   (배율은 저장되어 다음 실행 때 유지됩니다)\n\n" +
        "※ 시간은 모두 UTC 기준입니다.";

    private Panel BuildWelcome()
    {
        var p = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Background };
        var box = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Anchor = AnchorStyles.None, BackColor = Ui.Background };
        box.Controls.Add(new Label { Text = "Sysmon Analyzer", AutoSize = true, Font = new Font(Ui.FontName, 22f, FontStyle.Bold), ForeColor = Ui.Text, Anchor = AnchorStyles.None });
        box.Controls.Add(new Label { Text = "Sysmon 이벤트 로그(.evtx)를 열거나 이 창에 끌어다 놓으세요.", AutoSize = true, Font = new Font(Ui.FontName, 11f), ForeColor = Ui.Muted, Anchor = AnchorStyles.None, Margin = new Padding(0, 8, 0, 16) });
        var buttons = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.None };
        var open = new Button { Text = "파일 열기...", AutoSize = true, Padding = new Padding(12, 6, 12, 6) };
        var local = new Button { Text = "로컬 Sysmon 로그", AutoSize = true, Padding = new Padding(12, 6, 12, 6) };
        open.Click += async (_, _) => await OpenDialog(false);
        local.Click += async (_, _) => await LoadLocalAsync();
        buttons.Controls.AddRange(new Control[] { open, local });
        var samples = FindSamples();
        if (samples.Length > 0)
        {
            var sample = new Button { Text = $"샘플 열기 ({samples.Length}개)", AutoSize = true, Padding = new Padding(12, 6, 12, 6) };
            sample.Click += async (_, _) => await LoadFilesAsync(samples, false);
            buttons.Controls.Add(sample);
        }
        box.Controls.Add(buttons);
        p.Controls.Add(box);
        p.Resize += (_, _) => box.Location = new Point((p.Width - box.Width) / 2, (p.Height - box.Height) / 2 - 40);
        return p;
    }

    /// <summary>실행 파일 기준 상위 폴더들에서 samples\*.evtx 탐색.</summary>
    private static string[] FindSamples()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.Parent)
        {
            var s = Path.Combine(dir.FullName, "samples");
            if (Directory.Exists(s))
            {
                var files = Directory.GetFiles(s, "*.evtx");
                if (files.Length > 0) return files;
            }
        }
        return Array.Empty<string>();
    }

    // ---- 로딩 ----
    private async Task OpenDialog(bool append)
    {
        using var dlg = new OpenFileDialog
        {
            Filter = "Sysmon 로그 (*.evtx;*.xml)|*.evtx;*.xml|모든 파일 (*.*)|*.*",
            Multiselect = true,
            Title = append ? "추가할 Sysmon 로그 선택" : "Sysmon 로그 열기",
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
            await LoadFilesAsync(dlg.FileNames, append);
    }

    public async Task LoadFilesAsync(IEnumerable<string> files, bool append)
    {
        var list = files.Where(File.Exists).ToList();
        if (list.Count == 0) return;
        await RunLoad(append, (progress, ct) =>
        {
            var all = new List<SysmonEvent>();
            foreach (var f in list)
                all.AddRange(EventLoader.LoadFile(f, progress, ct));
            return (all, list.Select(f => Path.GetFileName(f)!).ToList());
        });
    }

    private async Task LoadLocalAsync()
    {
        await RunLoad(false, (progress, ct) =>
            (EventLoader.LoadLocalChannel(progress, ct), new List<string> { "로컬 Sysmon 채널" }));
    }

    private async Task RunLoad(bool append, Func<IProgress<string>, CancellationToken, (List<SysmonEvent>, List<string>)> loader)
    {
        if (_busy) return;
        _busy = true;
        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(s => _status.Text = s);
        _progress.Visible = true;
        UseWaitCursor = true;
        var sw = Stopwatch.StartNew();
        try
        {
            var prev = append ? _loaded.ToList() : new List<SysmonEvent>();
            var prevSources = append ? _sources.ToList() : new List<string>();
            var (events, sources, result) = await Task.Run(() =>
            {
                var (ev, src) = loader(progress, _cts.Token);
                ((IProgress<string>)progress).Report($"분석 중... ({ev.Count:N0}건)");
                var merged = prev.Concat(ev).GroupBy(e => (e.Computer, e.RecordId, e.EventId, e.Time)).Select(g => g.First()).ToList();
                var allSources = prevSources.Concat(src).Distinct().ToList();
                return (merged, allSources, AnalysisResult.Build(merged, allSources));
            });
            _loaded.Clear();
            _loaded.AddRange(events);
            _sources.Clear();
            _sources.AddRange(sources);
            Bind(result);
            _status.Text = $"{string.Join(", ", sources)} · 이벤트 {events.Count:N0}건 · 프로세스 {result.Processes.Count:N0}개 · " +
                           $"연결 {result.Connections.Count:N0}건 · 경고 {result.Alerts.Count:N0}건 · {sw.Elapsed.TotalSeconds:0.0}초";
        }
        catch (OperationCanceledException)
        {
            _status.Text = "취소됨";
        }
        catch (UnauthorizedAccessException ex)
        {
            _status.Text = "권한 오류";
            MessageBox.Show(this, "로그에 접근할 권한이 없습니다. 관리자 권한으로 실행하세요.\n\n" + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            _status.Text = "불러오기 실패";
            MessageBox.Show(this, "로그를 불러오지 못했습니다.\n\n" + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _progress.Visible = false;
            UseWaitCursor = false;
            _busy = false;
        }
    }

    public void Bind(AnalysisResult r)
    {
        Result = r;
        bool has = r.Events.Count > 0;
        _tabs.Visible = has;
        _welcome.Visible = !has;
        Text = has ? $"Sysmon Analyzer - {string.Join(", ", r.Sources)}" : "Sysmon Analyzer";
        _dash.Bind(r);
        _tree.Bind(r);
        _track.Bind(r);
        _net.Bind(r);
        _alerts.Bind(r);
        _events.Bind(r);
        _tpAlerts.Text = r.Alerts.Count > 0 ? $"탐지 결과 ({r.Alerts.Count})" : "탐지 결과";
        _tabs.SelectedTab = _tpDash;
        if (!has) _status.Text = "EVTX 파일을 열거나 창에 끌어다 놓으세요.";
    }

    // ---- 내보내기 ----
    private void ExportCsv()
    {
        if (Result.Events.Count == 0) return;
        using var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "sysmon_events.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        _events.ExportCsv(dlg.FileName);
        _status.Text = $"CSV 저장: {dlg.FileName} ({_events.CurrentView.Count:N0}건)";
    }

    private void ExportReport()
    {
        if (Result.Events.Count == 0) return;
        using var dlg = new SaveFileDialog { Filter = "HTML (*.html)|*.html", FileName = "sysmon_report.html" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, ReportWriter.Build(Result), new System.Text.UTF8Encoding(true));
        _status.Text = $"보고서 저장: {dlg.FileName}";
        try { Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true }); } catch { }
    }

    // ---- INavigator ----
    public void ShowProcessTree(ProcessInfo p)
    {
        _tabs.SelectedTab = _tpTree;
        _tree.SelectInTree(p, refocusGraph: true);
    }

    public void ShowProcessTrack(ProcessInfo p)
    {
        _tabs.SelectedTab = _tpTrack;
        _track.ShowProcess(p);
    }

    public void ShowProcessTrackByImage(string image)
    {
        _tabs.SelectedTab = _tpTrack;
        _track.SelectImage(image);
    }

    public void ShowEvents(string? text = null, int? eventId = null, DateTime? from = null, DateTime? to = null)
    {
        _tabs.SelectedTab = _tpEvents;
        _events.SetFilter(text, eventId, from, to);
    }

    public void ShowNetwork(string? filter)
    {
        _tabs.SelectedTab = _tpNet;
        _net.SetFilter(filter);
    }

    public void ShowAlerts() => _tabs.SelectedTab = _tpAlerts;

    // ---- 스냅샷(자동 검증) 지원 ----
    internal TabControl Tabs => _tabs;
    internal ProcessTreeView TreeView => _tree;
    internal ProcessTrackView TrackView => _track;
}
