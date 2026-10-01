using System.Drawing.Drawing2D;
using System.Reflection;

namespace SysmonAnalyzer.Controls;

/// <summary>공통 색상, 폰트, DPI 보정, ListView 유틸리티.</summary>
public static class Ui
{
    public static readonly Color Background = Color.FromArgb(246, 248, 250);
    public static readonly Color Surface = Color.White;
    public static readonly Color Border = Color.FromArgb(208, 215, 222);
    public static readonly Color Text = Color.FromArgb(31, 35, 40);
    public static readonly Color Muted = Color.FromArgb(101, 109, 118);
    public static readonly Color Accent = Color.FromArgb(9, 105, 218);
    public static readonly Color AccentSoft = Color.FromArgb(221, 236, 255);
    public static readonly Color Gridline = Color.FromArgb(234, 238, 242);

    public const string FontName = "Malgun Gothic";

    // ---- 화면 확대(Ctrl+휠 / Ctrl+ +,-,0) ----
    public const float MinZoom = 0.7f, MaxZoom = 2.5f;

    /// <summary>사용자 확대 배율 (1 = 100%). DPI 배율과 별개로 곱해진다.</summary>
    public static float Zoom { get; private set; } = 1f;

    public static event EventHandler? ZoomChanged;

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Control, Font> BaseFonts = new();

    /// <summary>DPI × 사용자 확대 배율.</summary>
    public static float Scale(Control c) => c.DeviceDpi / 96f * Zoom;

    public static int S(Control c, int px) => (int)Math.Round(px * Scale(c));

    /// <summary>그리기용 폰트 (사용자 확대 배율 반영, 포인트 단위).</summary>
    public static Font F(float size, FontStyle style = FontStyle.Regular) => new(FontName, size * Zoom, style);

    /// <summary>
    /// 확대 배율을 바꾸고 root 아래 모든 컨트롤의 폰트·ListView 컬럼 폭·고정 높이 제목을 갱신한다.
    /// 각 컨트롤의 100% 기준 폰트는 처음 적용 시점에 기억해 두므로 반복해도 오차가 누적되지 않는다.
    /// </summary>
    public static void SetZoom(Control root, float zoom)
    {
        zoom = (float)Math.Round(Math.Clamp(zoom, MinZoom, MaxZoom), 2);
        if (Math.Abs(zoom - Zoom) < 0.001f) return;
        float ratio = zoom / Zoom;
        // 1단계: 부모 폰트를 바꾸기 전에 모든 컨트롤의 100% 기준 폰트를 기록 (상속 폰트 때문)
        CaptureBaseFonts(root, Zoom);
        Zoom = zoom;
        root.SuspendLayout();
        try { Apply(root, ratio); }
        finally { root.ResumeLayout(true); }
        ZoomChanged?.Invoke(null, EventArgs.Empty);
        root.Invalidate(true);
    }

    private static void CaptureBaseFonts(Control c, float currentZoom)
    {
        if (!BaseFonts.TryGetValue(c, out _))
        {
            var f = c.Font;
            BaseFonts.Add(c, new Font(f.FontFamily, f.SizeInPoints / currentZoom, f.Style, GraphicsUnit.Point));
        }
        foreach (Control child in c.Controls) CaptureBaseFonts(child, currentZoom);
    }

    private static void Apply(Control c, float ratio)
    {
        if (BaseFonts.TryGetValue(c, out var baseFont))
            c.Font = new Font(baseFont.FontFamily, baseFont.SizeInPoints * Zoom, baseFont.Style, GraphicsUnit.Point);

        if (c is ListView lv)
            foreach (ColumnHeader col in lv.Columns)
                col.Width = Math.Max(20, (int)Math.Round(col.Width * ratio));
        if (c is Label { AutoSize: false, Dock: DockStyle.Top or DockStyle.Bottom } label)
            label.Height = (int)Math.Round(label.Height * ratio);

        foreach (Control child in c.Controls) Apply(child, ratio);
    }

    /// <summary>
    /// 폼 어디에서든 Ctrl+마우스 휠을 가로채 확대/축소 요청을 보낸다.
    /// (자식 컨트롤이 휠을 먼저 소비하지 않도록 메시지 필터로 처리)
    /// </summary>
    public sealed class CtrlWheelFilter : IMessageFilter
    {
        private const int WM_MOUSEWHEEL = 0x020A;
        private readonly Form _form;
        private readonly Action<int> _onStep;
        private int _accum;

        public CtrlWheelFilter(Form form, Action<int> onStep)
        {
            _form = form;
            _onStep = onStep;
        }

        public bool PreFilterMessage(ref Message m)
        {
            if (m.Msg != WM_MOUSEWHEEL || (Control.ModifierKeys & Keys.Control) == 0) return false;
            if (Form.ActiveForm != _form) return false;
            int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
            _accum += delta;
            // 터치패드처럼 작은 delta도 누적해서 한 칸(120)마다 한 단계
            while (Math.Abs(_accum) >= 120)
            {
                int step = Math.Sign(_accum);
                _accum -= step * 120;
                _onStep(step);
            }
            return true;
        }
    }

    public static string Time(DateTime t) => t.ToString("yyyy-MM-dd HH:mm:ss.fff");

    public static string Time(DateTime? t) => t.HasValue ? Time(t.Value) : "";

    public static GraphicsPath RoundRect(RectangleF r, float radius)
    {
        var path = new GraphicsPath();
        float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
        if (d <= 0.5f) { path.AddRectangle(r); return path; }
        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static Color Blend(Color a, Color b, float t) => Color.FromArgb(
        (int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));

    public static void EnableDoubleBuffer(Control c) =>
        typeof(Control).GetProperty("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(c, true);

    public static ListView NewListView(params (string Title, int Width)[] columns)
    {
        var lv = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HideSelection = false,
            MultiSelect = false,
            Dock = DockStyle.Fill,
            BorderStyle = BorderStyle.None,
        };
        EnableDoubleBuffer(lv);
        foreach (var (title, width) in columns)
            lv.Columns.Add(title, S(lv, width));
        return lv;
    }

    /// <summary>일반(비가상) ListView에 컬럼 클릭 정렬 기능을 붙인다.</summary>
    public static void EnableSorting(ListView lv)
    {
        var sorter = new ListViewSorter();
        lv.ListViewItemSorter = sorter;
        lv.ColumnClick += (_, e) =>
        {
            if (sorter.Column == e.Column) sorter.Descending = !sorter.Descending;
            else { sorter.Column = e.Column; sorter.Descending = false; }
            lv.Sort();
        };
    }

    /// <summary>SplitContainer 분할 비율 설정 (범위를 벗어나도 예외 없이).</summary>
    public static void SetSplit(SplitContainer sc, double ratio)
    {
        int total = sc.Orientation == Orientation.Vertical ? sc.Width : sc.Height;
        int d = (int)(total * ratio);
        int min = sc.Panel1MinSize, max = total - sc.Panel2MinSize - sc.SplitterWidth;
        if (max <= min) return;
        try { sc.SplitterDistance = Math.Clamp(d, min, max); } catch (InvalidOperationException) { }
    }

    /// <summary>컨트롤이 실제 크기를 갖게 된 첫 시점에 분할 비율을 적용.</summary>
    public static void SplitOnShow(SplitContainer sc, double ratio)
    {
        void Handler(object? s, EventArgs e)
        {
            int total = sc.Orientation == Orientation.Vertical ? sc.Width : sc.Height;
            if (!sc.Visible || total < 200) return;
            sc.SizeChanged -= Handler;
            sc.VisibleChanged -= Handler;
            SetSplit(sc, ratio);
        }
        sc.SizeChanged += Handler;
        sc.VisibleChanged += Handler;
    }

    public static Label SectionTitle(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Top,
        Height = 26,
        TextAlign = ContentAlignment.MiddleLeft,
        Font = new Font(FontName, 9.5f, FontStyle.Bold),
        ForeColor = Text,
        Padding = new Padding(4, 0, 0, 0),
    };

    private sealed class ListViewSorter : System.Collections.IComparer
    {
        public int Column { get; set; } = -1;
        public bool Descending { get; set; }

        public int Compare(object? x, object? y)
        {
            if (Column < 0 || x is not ListViewItem a || y is not ListViewItem b) return 0;
            var sa = Column < a.SubItems.Count ? a.SubItems[Column].Text : "";
            var sb = Column < b.SubItems.Count ? b.SubItems[Column].Text : "";
            int r = double.TryParse(sa.Replace(",", ""), out var da) && double.TryParse(sb.Replace(",", ""), out var db)
                ? da.CompareTo(db)
                : string.Compare(sa, sb, StringComparison.CurrentCultureIgnoreCase);
            return Descending ? -r : r;
        }
    }
}
