using System.Text;
using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Controls;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Forms;

/// <summary>전체 이벤트 목록 (가상 ListView) + 필터 + 상세.</summary>
public sealed class EventsView : UserControl
{
    private readonly INavigator _nav;
    private AnalysisResult _r = AnalysisResult.Empty;
    private List<SysmonEvent> _view = new();
    private DateTime? _from, _to;
    private int _sortCol = 0;
    private bool _sortDesc;

    private readonly TextBox _filter = new() { PlaceholderText = "검색어 (모든 필드, 공백=AND, -제외어)", Width = 340 };
    private readonly ComboBox _id = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 230 };
    private readonly Button _clearTime = new() { AutoSize = true, Visible = false };
    private readonly Label _count = new() { AutoSize = true, ForeColor = Ui.Muted, Padding = new Padding(8, 6, 0, 0) };
    private readonly ListView _list = Ui.NewListView(("시각(UTC)", 175), ("ID", 40), ("유형", 130), ("프로세스", 130), ("PID", 55), ("컴퓨터", 100), ("내용", 800));
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.None, BackColor = Color.White };

    public EventsView(INavigator nav)
    {
        _nav = nav;
        Dock = DockStyle.Fill;
        BackColor = Ui.Background;

        var toProc = new Button { Text = "프로세스 추적", AutoSize = true };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Ui.Surface };
        bar.Controls.AddRange(new Control[] { _filter, _id, _clearTime, toProc, _count });

        _list.VirtualMode = true;
        _list.RetrieveVirtualItem += (_, e) => e.Item = MakeRow(_view[e.ItemIndex]);
        _list.ColumnClick += (_, e) =>
        {
            if (_sortCol == e.Column) _sortDesc = !_sortDesc; else { _sortCol = e.Column; _sortDesc = false; }
            Apply();
        };

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        split.Panel1.Controls.Add(_list);
        split.Panel2.Controls.Add(_detail);
        Controls.Add(split);
        Controls.Add(bar);
        Ui.SplitOnShow(split, 0.65);

        var timer = new System.Windows.Forms.Timer { Interval = 350 };
        timer.Tick += (_, _) => { timer.Stop(); Apply(); };
        _filter.TextChanged += (_, _) => { timer.Stop(); timer.Start(); };
        _id.SelectedIndexChanged += (_, _) => Apply();
        _clearTime.Click += (_, _) => { _from = _to = null; Apply(); };
        _list.SelectedIndexChanged += (_, _) => _detail.Text = EventFormat.Details(Current);
        _list.DoubleClick += (_, _) => GoToProcess();
        toProc.Click += (_, _) => GoToProcess();
    }

    private SysmonEvent? Current => _list.SelectedIndices.Count > 0 ? _view[_list.SelectedIndices[0]] : null;

    public IReadOnlyList<SysmonEvent> CurrentView => _view;

    private void GoToProcess()
    {
        if (Current is { } e && _r.Processes.TryGetValue(e.ProcessGuid, out var p)) _nav.ShowProcessTrack(p);
    }

    public void Bind(AnalysisResult r)
    {
        _r = r;
        _from = _to = null;
        _id.Items.Clear();
        _id.Items.Add(new IdItem(null, $"전체 유형 ({r.Events.Count:N0})"));
        foreach (var g in r.Events.GroupBy(e => e.EventId).OrderBy(g => g.Key))
            _id.Items.Add(new IdItem(g.Key, $"[{g.Key}] {EventCatalog.Get(g.Key).Korean} ({g.Count():N0})"));
        _id.SelectedIndex = 0;
        Apply();
    }

    public void SetFilter(string? text, int? eventId, DateTime? from, DateTime? to)
    {
        _from = from;
        _to = to;
        _filter.Text = text ?? "";
        _id.SelectedIndex = Math.Max(0, _id.Items.Cast<IdItem>().ToList().FindIndex(i => i.Id == eventId));
        Apply();
    }

    private void Apply()
    {
        var terms = _filter.Text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var include = terms.Where(t => !t.StartsWith('-') || t.Length == 1).ToArray();
        var exclude = terms.Where(t => t.StartsWith('-') && t.Length > 1).Select(t => t[1..]).ToArray();
        var id = (_id.SelectedItem as IdItem)?.Id;

        IEnumerable<SysmonEvent> q = _r.Events;
        if (id.HasValue) q = q.Where(e => e.EventId == id);
        if (_from.HasValue) q = q.Where(e => e.Time >= _from && e.Time < _to);
        if (include.Length > 0 || exclude.Length > 0)
            q = q.Where(e =>
            {
                var hay = SearchText(e);
                return include.All(t => hay.Contains(t, StringComparison.OrdinalIgnoreCase)) &&
                       !exclude.Any(t => hay.Contains(t, StringComparison.OrdinalIgnoreCase));
            });

        Func<SysmonEvent, IComparable> key = _sortCol switch
        {
            1 => e => e.EventId,
            2 => e => EventCatalog.Get(e.EventId).Korean,
            3 => e => e.ImageName.ToLowerInvariant(),
            4 => e => e.ProcessId,
            5 => e => e.Computer,
            6 => e => e.Summary,
            _ => e => e.Index,
        };
        q = _sortDesc ? q.OrderByDescending(key) : q.OrderBy(key);
        _view = q.ToList();

        _clearTime.Visible = _from.HasValue;
        if (_from.HasValue) _clearTime.Text = $"시간 필터 해제 ✕ ({_from:MM-dd HH:mm:ss} ~ {_to:HH:mm:ss})";
        _list.VirtualListSize = 0;
        _list.VirtualListSize = _view.Count;
        _list.Invalidate();
        _count.Text = $"{_view.Count:N0}건 / 전체 {_r.Events.Count:N0}건";
        _detail.Clear();
    }

    private static string SearchText(SysmonEvent e)
    {
        var sb = new StringBuilder();
        sb.Append(e.EventId).Append(' ').Append(EventCatalog.Get(e.EventId).Name).Append(' ').Append(e.Computer).Append(' ');
        foreach (var v in e.Data.Values) sb.Append(v).Append(' ');
        return sb.ToString();
    }

    private static ListViewItem MakeRow(SysmonEvent e)
    {
        var info = EventCatalog.Get(e.EventId);
        var item = new ListViewItem(new[]
        {
            Ui.Time(e.Time), e.EventId.ToString(), info.Korean, e.ImageName, e.ProcessId == 0 ? "" : e.ProcessId.ToString(),
            e.Computer, e.Summary,
        }) { UseItemStyleForSubItems = false };
        item.SubItems[2].ForeColor = info.Color;
        return item;
    }

    /// <summary>현재 필터 결과를 CSV로 저장.</summary>
    public void ExportCsv(string path)
    {
        var keys = _view.SelectMany(e => e.Data.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        using var w = new StreamWriter(path, false, new UTF8Encoding(true));
        w.WriteLine(string.Join(",", new[] { "TimeUtc", "EventId", "EventType", "Computer", "RecordId", "Source" }.Concat(keys).Select(EventFormat.Csv)));
        foreach (var e in _view)
        {
            var cols = new List<string> { Ui.Time(e.Time), e.EventId.ToString(), EventCatalog.Get(e.EventId).Name, e.Computer, e.RecordId.ToString(), e.SourceFile };
            cols.AddRange(keys.Select(e.Get));
            w.WriteLine(string.Join(",", cols.Select(EventFormat.Csv)));
        }
    }

    private sealed record IdItem(int? Id, string Text)
    {
        public override string ToString() => Text;
    }
}
