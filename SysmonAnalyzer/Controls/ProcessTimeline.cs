using System.Drawing.Drawing2D;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Controls;

/// <summary>
/// SysmonView의 Process View처럼 한 프로세스 세션에서 일어난 이벤트를 시간순 체인으로 그린다.
/// 자신의 이벤트 + 자식 프로세스 생성 + 다른 프로세스로부터의 접근(8/10)을 함께 보여준다.
/// </summary>
public sealed class ProcessTimeline : Panel
{
    private enum ItemKind { Own, ChildCreate, Incoming }

    private sealed class Item
    {
        public ItemKind Kind;
        public SysmonEvent Event = null!;
        public ProcessInfo? Link;
        public int Count = 1;
        public string Title = "";
        public string Detail = "";
        public string GroupKey = "";
        public Color Color;
        public RectangleF Rect;
        public DateTime LastTime;
    }

    private ProcessInfo? _proc;
    private readonly List<Item> _items = new();
    private Item? _selected, _hover;
    private RectangleF _header, _parentLink;
    private readonly ToolTip _tip = new() { AutoPopDelay = 20000 };

    public bool GroupRepeats { get; set; } = true;
    public HashSet<EventCategory> Categories { get; } = Enum.GetValues<EventCategory>().ToHashSet();
    public bool IncludeChildren { get; set; } = true;

    public event EventHandler<SysmonEvent>? EventSelected;
    public event EventHandler<ProcessInfo>? ProcessActivated;

    public ProcessTimeline()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
        AutoScroll = true;
        BackColor = Color.FromArgb(250, 251, 252);
        Font = new Font(Ui.FontName, 9f);
    }

    public ProcessInfo? Process => _proc;

    public void ShowProcess(ProcessInfo? p)
    {
        _proc = p;
        _selected = null;
        Rebuild();
        AutoScrollPosition = Point.Empty;
    }

    public void Rebuild()
    {
        _items.Clear();
        _hover = null;
        if (_proc != null)
        {
            var raw = new List<Item>();
            foreach (var e in _proc.Events)
            {
                if (e.EventId == 1 && e.ProcessGuid == _proc.Guid) continue; // 헤더로 표시
                if (!Categories.Contains(EventCatalog.Get(e.EventId).Category)) continue;
                raw.Add(MakeOwn(e));
            }
            if (IncludeChildren && Categories.Contains(EventCategory.Process))
            {
                foreach (var c in _proc.Children.Where(c => c.CreateEvent != null))
                {
                    raw.Add(new Item
                    {
                        Kind = ItemKind.ChildCreate,
                        Event = c.CreateEvent!,
                        Link = c,
                        Title = $"자식 프로세스 생성 → {c.Name} (PID {c.Pid})",
                        Detail = c.CommandLine,
                        GroupKey = "child:" + c.Guid,
                        Color = EventCatalog.Get(1).Color,
                    });
                }
            }
            foreach (var e in _proc.IncomingEvents)
            {
                if (!Categories.Contains(EventCatalog.Get(e.EventId).Category)) continue;
                raw.Add(new Item
                {
                    Kind = ItemKind.Incoming,
                    Event = e,
                    Title = $"[{e.EventId}] {EventCatalog.Get(e.EventId).Korean} ← {SysmonEvent.FileName(e.Get("SourceImage"))}",
                    Detail = e.Summary,
                    GroupKey = $"in:{e.EventId}:{e.Get("SourceProcessGuid")}:{e.Get("GrantedAccess")}",
                    Color = EventCatalog.Get(e.EventId).Color,
                });
            }
            raw.Sort((a, b) => a.Event.Time != b.Event.Time ? a.Event.Time.CompareTo(b.Event.Time) : a.Event.Index.CompareTo(b.Event.Index));

            foreach (var it in raw)
            {
                it.LastTime = it.Event.Time;
                var prev = _items.Count > 0 ? _items[^1] : null;
                if (GroupRepeats && prev != null && prev.GroupKey == it.GroupKey && it.Kind != ItemKind.ChildCreate)
                {
                    prev.Count++;
                    prev.LastTime = it.Event.Time;
                    continue;
                }
                _items.Add(it);
            }
        }
        LayoutItems();
        Invalidate();
    }

    private static Item MakeOwn(SysmonEvent e)
    {
        var info = EventCatalog.Get(e.EventId);
        string title = $"[{e.EventId}] {info.Korean}";
        string detail = e.Summary;
        string key = $"{e.EventId}:{detail}";
        switch (e.EventId)
        {
            case 3:
                bool outbound = Analysis.AnalysisResult.IsTrue(e.Get("Initiated"));
                title += outbound
                    ? $"  →  {IpUtil.Endpoint(e.Get("DestinationIp"), e.GetInt("DestinationPort"))}"
                    : $"  ⇠  {IpUtil.Endpoint(e.Get("SourceIp"), e.GetInt("SourcePort"))}";
                key = $"3:{e.Get("Protocol")}:{e.Get("SourceIp")}:{e.Get("DestinationIp")}:{e.Get("DestinationPort")}:{outbound}";
                break;
            case 2:
            case 11:
            case 23:
            case 26:
                title += "  " + SysmonEvent.FileName(e.Get("TargetFilename"));
                key = $"{e.EventId}:{e.Get("TargetFilename")}";
                break;
            case 22:
                title += "  " + e.Get("QueryName");
                key = $"22:{e.Get("QueryName")}";
                break;
            case 7:
                title += "  " + SysmonEvent.FileName(e.Get("ImageLoaded"));
                key = "7:*"; // DLL 로드는 연속 구간을 묶는다
                break;
            case 12:
            case 13:
            case 14:
                key = $"{e.EventId}:{e.Get("TargetObject")}";
                break;
        }
        return new Item { Kind = ItemKind.Own, Event = e, Title = title, Detail = detail, GroupKey = key, Color = info.Color };
    }

    // ---- 레이아웃 ----
    private float S => Ui.Scale(this);
    private float TimeColW => 150 * S;
    private float SpineX => 14 * S + TimeColW + 12 * S;
    private float BoxX => SpineX + 22 * S;

    private void LayoutItems()
    {
        float s = S;
        float w = Math.Max(500 * s, ClientSize.Width - SystemInformation.VerticalScrollBarWidth - BoxX - 16 * s);
        float y = 12 * s;
        _header = new RectangleF(14 * s, y, BoxX + w - 14 * s, _proc == null ? 0 : 108 * s);
        y += _header.Height + 22 * s;
        float h = 46 * s;
        foreach (var it in _items)
        {
            it.Rect = new RectangleF(BoxX, y, w, h);
            y += h + 8 * s;
        }
        AutoScrollMinSize = new Size((int)(BoxX + w + 16 * s), (int)(y + 20 * s));
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        LayoutItems();
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        LayoutItems(); // 확대 배율 변경 시 박스 크기 재계산
        Invalidate();
    }

    // ---- 그리기 ----
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        float s = S;
        using var muted = new SolidBrush(Ui.Muted);
        if (_proc == null)
        {
            g.DrawString("왼쪽에서 프로세스(세션)를 선택하면 이벤트 흐름이 표시됩니다.", Font, muted, 16 * s, 16 * s);
            return;
        }
        g.TranslateTransform(AutoScrollPosition.X, AutoScrollPosition.Y);
        var clip = new RectangleF(-AutoScrollPosition.X, -AutoScrollPosition.Y, ClientSize.Width, ClientSize.Height);

        DrawHeader(g, s);

        using var text = new SolidBrush(Ui.Text);
        using var bold = Ui.F(9f, FontStyle.Bold);
        using var small = Ui.F(8.5f);
        var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };

        // 척추선
        if (_items.Count > 0)
        {
            using var spine = new Pen(Color.FromArgb(200, 208, 216), 2 * s);
            g.DrawLine(spine, SpineX, _header.Bottom, SpineX, _items[^1].Rect.Top + _items[^1].Rect.Height / 2);
        }
        else
        {
            g.DrawString("선택한 필터에 해당하는 이벤트가 없습니다.", Font, muted, BoxX, _header.Bottom + 20 * s);
        }

        foreach (var it in _items)
        {
            var r = it.Rect;
            if (r.Bottom < clip.Top || r.Top > clip.Bottom) continue;
            float cy = r.Top + r.Height / 2;

            // 시간
            g.DrawString(it.Event.Time.ToString("MM-dd HH:mm:ss.fff"), small, muted,
                new RectangleF(14 * s, cy - 9 * s, TimeColW, 18 * s),
                new StringFormat { Alignment = StringAlignment.Far });

            // 척추 점 + 연결선
            using (var dot = new SolidBrush(it.Color))
                g.FillEllipse(dot, SpineX - 5 * s, cy - 5 * s, 10 * s, 10 * s);
            using (var lp = new Pen(Color.FromArgb(200, 208, 216), 1.2f * s))
                g.DrawLine(lp, SpineX + 5 * s, cy, r.Left, cy);

            bool sel = it == _selected, hov = it == _hover;
            Color fill = it.Kind switch
            {
                ItemKind.ChildCreate => Color.FromArgb(236, 248, 238),
                ItemKind.Incoming => Color.FromArgb(255, 241, 236),
                _ => Color.White,
            };
            if (hov) fill = Ui.Blend(fill, Ui.AccentSoft, 0.6f);
            using (var path = Ui.RoundRect(r, 5 * s))
            using (var fb = new SolidBrush(fill))
            using (var pen = new Pen(sel ? Ui.Accent : Ui.Border, sel ? 2.2f * s : 1f))
            {
                g.FillPath(fb, path);
                g.DrawPath(pen, path);
            }
            using (var stripe = new SolidBrush(it.Color))
                g.FillRectangle(stripe, r.Left + 1, r.Top + 1, 5 * s, r.Height - 2);

            float tx = r.Left + 14 * s;
            float tw = r.Width - 20 * s;
            string title = it.Title;
            if (it.Count > 1)
            {
                var badge = $"×{it.Count}";
                var bsz = g.MeasureString(badge, bold);
                var br = new RectangleF(r.Right - bsz.Width - 16 * s, r.Top + 6 * s, bsz.Width + 8 * s, bsz.Height);
                using (var bp = Ui.RoundRect(br, br.Height / 2))
                using (var bb = new SolidBrush(it.Color))
                    g.FillPath(bb, bp);
                g.DrawString(badge, bold, Brushes.White, br.X + 4 * s, br.Y);
                tw -= br.Width + 8 * s;
            }
            g.DrawString(title, bold, text, new RectangleF(tx, r.Top + 5 * s, tw, 18 * s), fmt);
            var detail = it.Detail;
            if (it.Count > 1) detail = $"[{it.Event.Time:HH:mm:ss} ~ {it.LastTime:HH:mm:ss}]  " + detail;
            g.DrawString(detail, small, muted, new RectangleF(tx, r.Top + 25 * s, r.Width - 20 * s, 17 * s), fmt);
        }
    }

    private void DrawHeader(Graphics g, float s)
    {
        var p = _proc!;
        var r = _header;
        var level = p.MaxAlertLevel;
        using (var path = Ui.RoundRect(r, 6 * s))
        using (var fb = new SolidBrush(Color.FromArgb(232, 242, 255)))
        using (var pen = new Pen(level.HasValue ? Alert.LevelColor(level.Value) : Ui.Accent, 1.6f * s))
        {
            g.FillPath(fb, path);
            g.DrawPath(pen, path);
        }
        using var title = Ui.F(12f, FontStyle.Bold);
        using var normal = Ui.F(9f);
        using var link = Ui.F(9f, FontStyle.Underline);
        using var text = new SolidBrush(Ui.Text);
        using var muted = new SolidBrush(Ui.Muted);
        using var accent = new SolidBrush(Ui.Accent);
        var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
        float x = r.X + 12 * s, w = r.Width - 24 * s;

        g.DrawString($"{p.Name}   PID {p.Pid}", title, text, new RectangleF(x, r.Y + 8 * s, w, 24 * s), fmt);
        g.DrawString(p.Image, normal, muted, new RectangleF(x, r.Y + 34 * s, w, 18 * s), fmt);
        var life = $"시작 {Ui.Time(p.Start ?? p.FirstSeen)}   종료 {(p.End.HasValue ? Ui.Time(p.End) : "(기록 없음)")}   " +
                   $"사용자 {p.User}   무결성 {p.IntegrityLevel}   이벤트 {p.Events.Count}건";
        g.DrawString(life, normal, text, new RectangleF(x, r.Y + 52 * s, w, 18 * s), fmt);
        g.DrawString("명령줄: " + (string.IsNullOrEmpty(p.CommandLine) ? "(알 수 없음)" : p.CommandLine), normal, text,
            new RectangleF(x, r.Y + 70 * s, w, 18 * s), fmt);

        var parentText = p.Parent != null ? $"부모: {p.Parent.Name} (PID {p.Parent.Pid})  ▶ 이동"
            : !string.IsNullOrEmpty(p.ParentImage) ? $"부모: {SysmonEvent.FileName(p.ParentImage)} (PID {p.ParentPid})" : "부모: (정보 없음)";
        var sz = g.MeasureString(parentText, link);
        _parentLink = new RectangleF(x, r.Y + 88 * s, Math.Min(sz.Width, w), 18 * s);
        g.DrawString(parentText, p.Parent != null ? link : normal, p.Parent != null ? accent : muted, _parentLink, fmt);
    }

    // ---- 입력 ----
    private PointF ToContent(Point p) => new(p.X - AutoScrollPosition.X, p.Y - AutoScrollPosition.Y);

    private Item? HitTest(Point p)
    {
        var c = ToContent(p);
        return _items.FirstOrDefault(i => i.Rect.Contains(c));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var h = HitTest(e.Location);
        bool overParent = _proc?.Parent != null && _parentLink.Contains(ToContent(e.Location));
        Cursor = overParent || h?.Link != null ? Cursors.Hand : Cursors.Default;
        if (h == _hover) return;
        _hover = h;
        _tip.SetToolTip(this, h == null ? "" :
            $"{h.Title}\n{Ui.Time(h.Event.Time)}{(h.Count > 1 ? $" ~ {Ui.Time(h.LastTime)} ({h.Count}건)" : "")}\n{h.Detail}" +
            (h.Link != null ? "\n(더블클릭: 자식 프로세스로 이동)" : ""));
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hover = null;
        Invalidate();
    }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        Focus();
        if (_proc?.Parent != null && _parentLink.Contains(ToContent(e.Location)))
        {
            ProcessActivated?.Invoke(this, _proc.Parent);
            return;
        }
        var h = HitTest(e.Location);
        if (h == null) return;
        _selected = h;
        Invalidate();
        EventSelected?.Invoke(this, h.Event);
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        var h = HitTest(e.Location);
        if (h?.Link != null) ProcessActivated?.Invoke(this, h.Link);
    }
}

