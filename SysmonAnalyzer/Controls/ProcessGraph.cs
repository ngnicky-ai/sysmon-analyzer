using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Controls;

/// <summary>
/// 부모→자식 프로세스 관계를 왼쪽→오른쪽 트리로 그리는 그래프.
/// 마우스 휠 확대/축소, 드래그 이동, 클릭 선택, 더블클릭 이동(ProcessActivated).
/// </summary>
public sealed class ProcessGraph : Control
{
    private enum NodeKind { Process, Network, More }

    private sealed class Node
    {
        public NodeKind Kind;
        public ProcessInfo? Proc;
        public string Title = "";
        public string Sub = "";
        public string Tip = "";
        public Node? Parent;
        public readonly List<Node> Children = new();
        public RectangleF Rect;
        public bool OnPath;     // 조상 경로 (형제 생략)
        public int HiddenSiblings;
    }

    private const float NodeW = 220, NodeH = 50, NetW = 190, NetH = 34, GapX = 70, GapY = 12, Pad = 30;
    private const int MaxNodes = 4000;
    private const int MaxNetPerProc = 12;

    private readonly List<Node> _nodes = new();
    private SizeF _world;
    private float _zoom = 1f;
    private PointF _pan;
    private Point _dragStart;
    private PointF _panStart;
    private bool _dragging, _moved;
    private Node? _hover;
    private ProcessInfo? _selected;
    private ProcessInfo? _focus;
    private readonly ToolTip _tip = new() { AutoPopDelay = 20000, InitialDelay = 300 };
    private bool _truncated;

    public bool ShowNetwork { get; set; } = true;
    public bool FullTree { get; set; }

    public ProcessInfo? SelectedProcess => _selected;

    /// <summary>노드 클릭.</summary>
    public event EventHandler<ProcessInfo>? ProcessClicked;
    /// <summary>노드 더블클릭.</summary>
    public event EventHandler<ProcessInfo>? ProcessActivated;

    public ProcessGraph()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
        BackColor = Color.FromArgb(250, 251, 252);
        TabStop = true;
    }

    /// <summary>선택 프로세스 중심 그래프: 조상 경로 + 선택 프로세스의 하위 트리 전체.</summary>
    public void ShowProcess(ProcessInfo? focus, IReadOnlyList<ProcessInfo> allRoots)
    {
        _focus = focus;
        _selected = focus;
        Rebuild(allRoots);
        if (focus != null) CenterOn(focus, resetZoom: true);
        else FitToView();
    }

    public void Rebuild(IReadOnlyList<ProcessInfo> allRoots)
    {
        _nodes.Clear();
        _hover = null;
        _truncated = false;
        var roots = new List<Node>();

        if (FullTree || _focus == null)
        {
            foreach (var r in allRoots)
            {
                if (_nodes.Count >= MaxNodes) { _truncated = true; break; }
                roots.Add(BuildSubtree(r, null, 0));
            }
        }
        else
        {
            var chain = _focus.Ancestors().Reverse().ToList();
            Node? parent = null;
            foreach (var a in chain)
            {
                var n = NewProcessNode(a, parent);
                n.OnPath = true;
                n.HiddenSiblings = a.Children.Count - 1;
                if (parent == null) roots.Add(n);
                parent = n;
            }
            var focusNode = BuildSubtree(_focus, parent, 0);
            if (parent == null) roots.Add(focusNode);
        }

        // 레이아웃: 잎 노드에 차례로 y를 배정하고 부모는 자식들의 가운데
        float y = Pad;
        foreach (var r in roots)
            y = LayoutNode(r, 0, y) + GapY * 2;
        float maxX = _nodes.Count == 0 ? 0 : _nodes.Max(n => n.Rect.Right);
        _world = new SizeF(maxX + Pad, y + Pad);
        Invalidate();
    }

    private Node NewProcessNode(ProcessInfo p, Node? parent)
    {
        var n = new Node
        {
            Kind = NodeKind.Process,
            Proc = p,
            Parent = parent,
            Title = p.Name,
            Sub = $"PID {p.Pid} · {(p.Start ?? p.FirstSeen):MM-dd HH:mm:ss} · 이벤트 {p.Events.Count}",
            Tip = BuildTip(p),
        };
        parent?.Children.Add(n);
        _nodes.Add(n);
        return n;
    }

    private static string BuildTip(ProcessInfo p)
    {
        var lines = new List<string>
        {
            p.Image,
            $"PID: {p.Pid}   사용자: {p.User}   무결성: {p.IntegrityLevel}",
            $"시작: {Ui.Time(p.Start)}   종료: {Ui.Time(p.End)}",
        };
        if (!string.IsNullOrEmpty(p.CommandLine)) lines.Add("명령줄: " + Trim(p.CommandLine, 300));
        if (!p.HasCreateEvent) lines.Add("(프로세스 생성 이벤트 없음 - 다른 이벤트로 추정)");
        lines.Add($"이벤트 {p.Events.Count}건 · 자식 {p.Children.Count}개 · 네트워크 {p.NetworkCount}건");
        foreach (var a in p.Alerts.Take(5)) lines.Add($"⚠ [{a.LevelText}] {a.Rule}");
        return string.Join("\n", lines);
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private Node BuildSubtree(ProcessInfo p, Node? parent, int depth)
    {
        var n = NewProcessNode(p, parent);
        if (ShowNetwork)
        {
            var groups = p.Events.Where(e => e.EventId == 3)
                .GroupBy(e => NetKey(e))
                .OrderByDescending(g => g.Count())
                .ToList();
            foreach (var g in groups.Take(MaxNetPerProc))
            {
                var first = g.First();
                var host = first.Get("DestinationHostname");
                var nn = new Node
                {
                    Kind = NodeKind.Network,
                    Parent = n,
                    Title = g.Key,
                    Sub = $"{first.Get("Protocol")} · {g.Count()}회" + (host.Length > 1 ? $" · {host}" : ""),
                    Tip = $"{g.Key}\n{first.Get("Protocol")} {g.Count()}회\n최초: {Ui.Time(first.Time)}\n최종: {Ui.Time(g.Last().Time)}",
                };
                n.Children.Add(nn);
                _nodes.Add(nn);
            }
            if (groups.Count > MaxNetPerProc)
            {
                var more = new Node { Kind = NodeKind.More, Parent = n, Title = $"… 네트워크 대상 {groups.Count - MaxNetPerProc}개 더" };
                n.Children.Add(more);
                _nodes.Add(more);
            }
        }
        foreach (var c in p.Children)
        {
            if (_nodes.Count >= MaxNodes)
            {
                _truncated = true;
                var more = new Node { Kind = NodeKind.More, Parent = n, Title = "… (노드 수 제한으로 생략)" };
                n.Children.Add(more);
                _nodes.Add(more);
                break;
            }
            if (depth < 200) BuildSubtree(c, n, depth + 1);
        }
        return n;
    }

    private static string NetKey(SysmonEvent e)
    {
        bool outbound = e.Get("Initiated").Equals("true", StringComparison.OrdinalIgnoreCase);
        return outbound
            ? "→ " + IpUtil.Endpoint(e.Get("DestinationIp"), e.GetInt("DestinationPort"))
            : "⇠ " + IpUtil.Endpoint(e.Get("SourceIp"), e.GetInt("SourcePort")) + " (수신 " + e.Get("DestinationPort") + ")";
    }

    private float LayoutNode(Node n, int depth, float y)
    {
        float x = Pad + depth * (NodeW + GapX);
        var (w, h) = n.Kind switch
        {
            NodeKind.Process => (NodeW, NodeH),
            NodeKind.Network => (NetW, NetH),
            _ => (NetW, 26f),
        };
        if (n.Children.Count == 0)
        {
            n.Rect = new RectangleF(x, y, w, h);
            return y + h + GapY;
        }
        float start = y;
        float cy = y;
        foreach (var c in n.Children) cy = LayoutNode(c, depth + 1, cy);
        float firstMid = n.Children[0].Rect.Top + n.Children[0].Rect.Height / 2;
        float lastMid = n.Children[^1].Rect.Top + n.Children[^1].Rect.Height / 2;
        float mid = (firstMid + lastMid) / 2;
        float top = Math.Max(start, mid - h / 2);
        n.Rect = new RectangleF(x, top, w, h);
        return Math.Max(cy, top + h + GapY);
    }

    // ---- 좌표 변환 ----
    private float EffZoom => _zoom * Ui.Scale(this);
    private PointF ToWorld(Point p) => new((p.X - _pan.X) / EffZoom, (p.Y - _pan.Y) / EffZoom);

    public void ZoomBy(float factor, Point? anchor = null)
    {
        var a = anchor ?? new Point(Width / 2, Height / 2);
        var w = ToWorld(a);
        _zoom = Math.Clamp(_zoom * factor, 0.1f, 3f);
        _pan = new PointF(a.X - w.X * EffZoom, a.Y - w.Y * EffZoom);
        Invalidate();
    }

    public void FitToView()
    {
        if (_world.Width <= 0 || Width <= 0) return;
        float s = Ui.Scale(this);
        _zoom = Math.Clamp(Math.Min(Width / (_world.Width * s), Height / (_world.Height * s)), 0.1f, 1.2f);
        _pan = new PointF((Width - _world.Width * EffZoom) / 2, Math.Max(0, (Height - _world.Height * EffZoom) / 2));
        Invalidate();
    }

    public void CenterOn(ProcessInfo p, bool resetZoom = false)
    {
        var n = _nodes.FirstOrDefault(x => x.Proc == p && x.Kind == NodeKind.Process);
        if (n == null) { FitToView(); return; }
        if (resetZoom)
        {
            float s = Ui.Scale(this);
            // 전체가 화면에 들어오면 맞춤, 아니면 100%
            float fit = Math.Min(Width / (_world.Width * s), Height / (_world.Height * s));
            _zoom = Math.Clamp(fit, 0.85f, 1f);
        }
        var c = new PointF(n.Rect.X + n.Rect.Width / 2, n.Rect.Y + n.Rect.Height / 2);
        // 선택 노드를 화면 왼쪽 1/3 지점에 배치 (자식이 오른쪽으로 펼쳐지므로)
        _pan = new PointF(Width * 0.33f - c.X * EffZoom, Height / 2f - c.Y * EffZoom);
        Invalidate();
    }

    public void Select(ProcessInfo? p)
    {
        _selected = p;
        Invalidate();
    }

    // ---- 그리기 ----
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        if (_nodes.Count == 0)
        {
            using var mb = new SolidBrush(Ui.Muted);
            using var f = Ui.F(10f);
            g.DrawString("프로세스를 선택하면 관계 그래프가 표시됩니다.", f, mb, 16, 16);
            return;
        }
        g.TranslateTransform(_pan.X, _pan.Y);
        g.ScaleTransform(EffZoom, EffZoom);
        DrawWorld(g, VisibleWorld());
        g.ResetTransform();

        using var hintFont = Ui.F(8.5f);
        using var hb = new SolidBrush(Ui.Muted);
        var hint = $"{_zoom * 100:0}%  ·  휠: 확대/축소  ·  드래그: 이동  ·  더블클릭: 해당 프로세스로 이동" +
                   (_truncated ? "  ·  ※ 노드가 많아 일부 생략됨" : "");
        g.DrawString(hint, hintFont, hb, 8, Height - hintFont.Height - 6);
    }

    private RectangleF VisibleWorld()
    {
        var a = ToWorld(Point.Empty);
        var b = ToWorld(new Point(Width, Height));
        return RectangleF.FromLTRB(a.X, a.Y, b.X, b.Y);
    }

    private void DrawWorld(Graphics g, RectangleF visible)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;

        // 간선
        using var edgePen = new Pen(Color.FromArgb(160, 170, 180), 1.4f);
        using var netEdge = new Pen(Color.FromArgb(120, 31, 111, 235), 1.2f) { DashStyle = DashStyle.Dash };
        using var pathPen = new Pen(Ui.Accent, 2.2f);
        foreach (var n in _nodes)
        {
            if (n.Parent == null) continue;
            var p = n.Parent.Rect;
            var c = n.Rect;
            if (Math.Max(p.Right, c.Right) < visible.Left || Math.Min(p.Left, c.Left) > visible.Right) continue;
            if (Math.Max(p.Bottom, c.Bottom) < visible.Top || Math.Min(p.Top, c.Top) > visible.Bottom) continue;
            var a = new PointF(p.Right, p.Top + p.Height / 2);
            var b = new PointF(c.Left, c.Top + c.Height / 2);
            float mx = (a.X + b.X) / 2;
            var pen = n.Kind == NodeKind.Network ? netEdge
                : (n.Parent.OnPath && (n.OnPath || n.Proc == _focus)) ? pathPen : edgePen;
            g.DrawBezier(pen, a, new PointF(mx, a.Y), new PointF(mx, b.Y), b);
        }

        using var titleFont = new Font(Ui.FontName, 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var subFont = new Font(Ui.FontName, 10.5f, GraphicsUnit.Pixel);
        using var textBrush = new SolidBrush(Ui.Text);
        using var mutedBrush = new SolidBrush(Ui.Muted);
        var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };

        foreach (var n in _nodes)
        {
            var r = n.Rect;
            if (!r.IntersectsWith(visible)) continue;
            switch (n.Kind)
            {
                case NodeKind.Process:
                    DrawProcessNode(g, n, titleFont, subFont, textBrush, mutedBrush, fmt);
                    break;
                case NodeKind.Network:
                    using (var path = Ui.RoundRect(r, r.Height / 2))
                    using (var fill = new SolidBrush(n == _hover ? Color.FromArgb(214, 232, 255) : Color.FromArgb(235, 244, 255)))
                    using (var pen = new Pen(Color.FromArgb(31, 111, 235), 1.2f))
                    {
                        g.FillPath(fill, path);
                        g.DrawPath(pen, path);
                    }
                    g.DrawString(n.Title, subFont, textBrush, new RectangleF(r.X + 12, r.Y + 3, r.Width - 18, 15), fmt);
                    g.DrawString(n.Sub, subFont, mutedBrush, new RectangleF(r.X + 12, r.Y + 17, r.Width - 18, 15), fmt);
                    break;
                default:
                    g.DrawString(n.Title, subFont, mutedBrush, new RectangleF(r.X + 4, r.Y + 5, r.Width, 16), fmt);
                    break;
            }
        }
    }

    private void DrawProcessNode(Graphics g, Node n, Font titleFont, Font subFont, Brush textBrush, Brush mutedBrush, StringFormat fmt)
    {
        var p = n.Proc!;
        var r = n.Rect;
        bool selected = p == _selected;
        var level = p.MaxAlertLevel;

        Color fill = Color.White;
        if (n.OnPath) fill = Color.FromArgb(244, 247, 250);
        if (p == _focus) fill = Color.FromArgb(232, 242, 255);
        if (n == _hover) fill = Ui.Blend(fill, Ui.AccentSoft, 0.7f);
        Color border = level.HasValue ? Alert.LevelColor(level.Value) : Color.FromArgb(175, 184, 193);
        float bw = selected ? 3f : level.HasValue ? 2f : 1.2f;
        if (selected) border = level.HasValue ? border : Ui.Accent;

        using (var shadow = Ui.RoundRect(new RectangleF(r.X + 1.5f, r.Y + 2, r.Width, r.Height), 6))
        using (var sb = new SolidBrush(Color.FromArgb(22, 0, 0, 0)))
            g.FillPath(sb, shadow);
        using (var path = Ui.RoundRect(r, 6))
        using (var fb = new SolidBrush(fill))
        using (var pen = new Pen(border, bw))
        {
            if (!p.HasCreateEvent) pen.DashStyle = DashStyle.Dash;
            g.FillPath(fb, path);
            g.DrawPath(pen, path);
        }

        // 왼쪽 색 띠: 종료됨(회색) / 실행 중(초록)
        var stripe = new RectangleF(r.X + 4, r.Y + 8, 4, r.Height - 16);
        using (var stripeBrush = new SolidBrush(p.End.HasValue ? Color.FromArgb(140, 150, 160) : Color.FromArgb(46, 160, 67)))
            g.FillRectangle(stripeBrush, stripe);

        float tx = r.X + 14;
        float badgeW = 0;
        if (level.HasValue)
        {
            badgeW = 18;
            var br = new RectangleF(r.Right - 22, r.Y + 6, 16, 16);
            using var bb = new SolidBrush(Alert.LevelColor(level.Value));
            g.FillEllipse(bb, br);
            using var wf = new Font(Ui.FontName, 10f, FontStyle.Bold, GraphicsUnit.Pixel);
            var cf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("!", wf, Brushes.White, br, cf);
        }
        g.DrawString(n.Title, titleFont, textBrush, new RectangleF(tx, r.Y + 7, r.Width - (tx - r.X) - 6 - badgeW, 17), fmt);
        g.DrawString(n.Sub, subFont, mutedBrush, new RectangleF(tx, r.Y + 27, r.Width - (tx - r.X) - 6, 15), fmt);

        if (n.HiddenSiblings > 0)
        {
            var t = $"+{n.HiddenSiblings}";
            using var sf = new Font(Ui.FontName, 9.5f, GraphicsUnit.Pixel);
            var sz = g.MeasureString(t, sf);
            g.DrawString(t, sf, mutedBrush, r.Right + 4, r.Bottom - sz.Height);
        }
    }

    // ---- 입력 ----
    private Node? HitTest(Point screen)
    {
        var w = ToWorld(screen);
        for (int i = _nodes.Count - 1; i >= 0; i--)
            if (_nodes[i].Rect.Contains(w)) return _nodes[i];
        return null;
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        if (e.Button is MouseButtons.Left or MouseButtons.Middle)
        {
            _dragging = true;
            _moved = false;
            _dragStart = e.Location;
            _panStart = _pan;
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_dragging)
        {
            int dx = e.X - _dragStart.X, dy = e.Y - _dragStart.Y;
            if (Math.Abs(dx) + Math.Abs(dy) > 3) _moved = true;
            if (_moved)
            {
                _pan = new PointF(_panStart.X + dx, _panStart.Y + dy);
                Cursor = Cursors.SizeAll;
                Invalidate();
            }
            return;
        }
        var h = HitTest(e.Location);
        if (h != _hover)
        {
            _hover = h;
            Cursor = h?.Proc != null ? Cursors.Hand : Cursors.Default;
            _tip.SetToolTip(this, h?.Tip ?? "");
            Invalidate();
        }
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        bool wasClick = _dragging && !_moved;
        _dragging = false;
        Cursor = Cursors.Default;
        if (wasClick && e.Button == MouseButtons.Left)
        {
            var h = HitTest(e.Location);
            if (h?.Proc != null)
            {
                _selected = h.Proc;
                Invalidate();
                ProcessClicked?.Invoke(this, h.Proc);
            }
        }
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        var h = HitTest(e.Location);
        if (h?.Proc != null) ProcessActivated?.Invoke(this, h.Proc);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        if (ModifierKeys.HasFlag(Keys.Shift))
        {
            _pan = new PointF(_pan.X + e.Delta / 2f, _pan.Y);
            Invalidate();
        }
        else
        {
            ZoomBy(e.Delta > 0 ? 1.15f : 1 / 1.15f, e.Location);
        }
    }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Left or Keys.Right or Keys.Up or Keys.Down || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        float step = 60;
        switch (e.KeyCode)
        {
            case Keys.Add: case Keys.Oemplus: ZoomBy(1.2f); break;
            case Keys.Subtract: case Keys.OemMinus: ZoomBy(1 / 1.2f); break;
            case Keys.D0: case Keys.NumPad0: FitToView(); break;
            case Keys.Left: _pan.X += step; Invalidate(); break;
            case Keys.Right: _pan.X -= step; Invalidate(); break;
            case Keys.Up: _pan.Y += step; Invalidate(); break;
            case Keys.Down: _pan.Y -= step; Invalidate(); break;
        }
    }

    /// <summary>그래프 전체를 PNG로 저장.</summary>
    public void SaveImage(string path)
    {
        const float scale = 1.5f;
        int w = (int)Math.Min(16000, _world.Width * scale);
        int h = (int)Math.Min(16000, _world.Height * scale);
        using var bmp = new Bitmap(Math.Max(1, w), Math.Max(1, h));
        using var g = Graphics.FromImage(bmp);
        g.Clear(Color.White);
        g.ScaleTransform(scale, scale);
        DrawWorld(g, new RectangleF(0, 0, _world.Width, _world.Height));
        bmp.Save(path, ImageFormat.Png);
    }
}
