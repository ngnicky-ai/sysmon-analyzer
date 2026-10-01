using System.Drawing.Drawing2D;
using SysmonAnalyzer.Models;

namespace SysmonAnalyzer.Controls;

/// <summary>시간대별 이벤트 발생량(유형별 누적 막대).</summary>
public sealed class TimeHistogram : Control
{
    private DateTime _start, _end;
    private TimeSpan _bucket;
    private int[,] _counts = new int[0, 0];
    private int[] _ids = Array.Empty<int>();
    private int _hover = -1;
    private readonly ToolTip _tip = new();

    public string Title { get; set; } = "이벤트 발생 추이";

    /// <summary>막대를 클릭하면 해당 구간 (시작, 끝)을 알린다.</summary>
    public event EventHandler<(DateTime From, DateTime To)>? BucketClicked;

    public TimeHistogram()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Ui.Surface;
        Font = new Font(Ui.FontName, 8.5f);
    }

    public void SetEvents(IReadOnlyList<SysmonEvent> events, int buckets = 60)
    {
        _hover = -1;
        if (events.Count == 0) { _counts = new int[0, 0]; Invalidate(); return; }
        _start = events.Min(e => e.Time);
        _end = events.Max(e => e.Time);
        var span = _end - _start;
        if (span.TotalSeconds < 1) span = TimeSpan.FromSeconds(1);
        _bucket = NiceBucket(TimeSpan.FromTicks(span.Ticks / buckets));
        _start = new DateTime(_start.Ticks - _start.Ticks % _bucket.Ticks, _start.Kind);
        int n = (int)((_end - _start).Ticks / _bucket.Ticks) + 1;
        _ids = events.Select(e => e.EventId).Distinct().OrderBy(i => i).ToArray();
        var idx = _ids.Select((id, i) => (id, i)).ToDictionary(x => x.id, x => x.i);
        _counts = new int[n, _ids.Length];
        foreach (var e in events)
            _counts[(int)((e.Time - _start).Ticks / _bucket.Ticks), idx[e.EventId]]++;
        Invalidate();
    }

    private static TimeSpan NiceBucket(TimeSpan raw)
    {
        TimeSpan[] steps =
        {
            TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30),
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30),
            TimeSpan.FromHours(1), TimeSpan.FromHours(3), TimeSpan.FromHours(6), TimeSpan.FromHours(12),
            TimeSpan.FromDays(1), TimeSpan.FromDays(7), TimeSpan.FromDays(30),
        };
        return steps.FirstOrDefault(s => s >= raw, TimeSpan.FromDays(Math.Ceiling(raw.TotalDays)));
    }

    private string BucketText(TimeSpan b) =>
        b.TotalDays >= 1 ? $"{b.TotalDays:0}일" : b.TotalHours >= 1 ? $"{b.TotalHours:0}시간" :
        b.TotalMinutes >= 1 ? $"{b.TotalMinutes:0}분" : $"{b.TotalSeconds:0}초";

    private RectangleF PlotRect()
    {
        float s = Ui.Scale(this);
        return new RectangleF(48 * s, 52 * s, Width - 60 * s, Height - 52 * s - 28 * s);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        float s = Ui.Scale(this);
        using var border = new Pen(Ui.Border);
        g.DrawRectangle(border, 0, 0, Width - 1, Height - 1);
        using var titleFont = Ui.F(10f, FontStyle.Bold);
        using var textBrush = new SolidBrush(Ui.Text);
        using var muted = new SolidBrush(Ui.Muted);
        g.DrawString(Title, titleFont, textBrush, 10 * s, 8 * s);

        int n = _counts.GetLength(0);
        if (n == 0)
        {
            g.DrawString("데이터 없음", Font, muted, 10 * s, 40 * s);
            return;
        }
        g.DrawString($"구간: {BucketText(_bucket)} (UTC) · 막대 클릭 시 해당 구간 이벤트 보기", Font, muted, 10 * s, 28 * s);

        // 범례
        float lx = Width - 10 * s;
        for (int k = _ids.Length - 1; k >= 0; k--)
        {
            var info = EventCatalog.Get(_ids[k]);
            var text = $"{info.Id} {info.Korean}";
            var sz = g.MeasureString(text, Font);
            lx -= sz.Width + 14 * s;
            if (lx < 200 * s) break;
            using var b = new SolidBrush(info.Color);
            g.FillRectangle(b, lx, 12 * s, 9 * s, 9 * s);
            g.DrawString(text, Font, muted, lx + 11 * s, 9 * s);
        }

        var plot = PlotRect();
        int max = 1;
        for (int i = 0; i < n; i++)
        {
            int sum = 0;
            for (int k = 0; k < _ids.Length; k++) sum += _counts[i, k];
            max = Math.Max(max, sum);
        }

        using var grid = new Pen(Ui.Gridline);
        for (int t = 0; t <= 4; t++)
        {
            float y = plot.Bottom - plot.Height * t / 4f;
            g.DrawLine(grid, plot.Left, y, plot.Right, y);
            var label = (max * t / 4).ToString("N0");
            var sz = g.MeasureString(label, Font);
            g.DrawString(label, Font, muted, plot.Left - sz.Width - 4 * s, y - sz.Height / 2);
        }

        float bw = plot.Width / n;
        for (int i = 0; i < n; i++)
        {
            float y = plot.Bottom;
            float x = plot.Left + i * bw;
            for (int k = 0; k < _ids.Length; k++)
            {
                int c = _counts[i, k];
                if (c == 0) continue;
                float h = plot.Height * c / max;
                var color = EventCatalog.Get(_ids[k]).Color;
                if (_hover >= 0 && _hover != i) color = Ui.Blend(color, Color.White, 0.55f);
                using var b = new SolidBrush(color);
                g.FillRectangle(b, x + Math.Min(1, bw * 0.1f), y - h, Math.Max(1, bw - Math.Max(1, bw * 0.2f)), h);
                y -= h;
            }
        }

        // X축 레이블
        int labels = Math.Max(2, (int)(plot.Width / (130 * s)));
        string fmt = _bucket.TotalDays >= 1 ? "yyyy-MM-dd" : (_end - _start).TotalDays >= 1 ? "MM-dd HH:mm" : "HH:mm:ss";
        for (int j = 0; j <= labels; j++)
        {
            int i = (int)((n - 1) * (j / (double)labels));
            var t = _start + TimeSpan.FromTicks(_bucket.Ticks * i);
            var text = t.ToString(fmt);
            var sz = g.MeasureString(text, Font);
            float x = plot.Left + i * bw + bw / 2 - sz.Width / 2;
            x = Math.Clamp(x, plot.Left - 20 * s, plot.Right - sz.Width);
            g.DrawString(text, Font, muted, x, plot.Bottom + 5 * s);
        }
    }

    private int HitTest(Point p)
    {
        var plot = PlotRect();
        int n = _counts.GetLength(0);
        if (n == 0 || p.X < plot.Left || p.X >= plot.Right || p.Y < plot.Top - 10 || p.Y > plot.Bottom) return -1;
        return Math.Clamp((int)((p.X - plot.Left) / (plot.Width / n)), 0, n - 1);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int h = HitTest(e.Location);
        if (h == _hover) return;
        _hover = h;
        Cursor = h >= 0 ? Cursors.Hand : Cursors.Default;
        Invalidate();
        if (h < 0) { _tip.SetToolTip(this, ""); return; }
        var from = _start + TimeSpan.FromTicks(_bucket.Ticks * h);
        var lines = new List<string> { $"{Ui.Time(from)} ~ {Ui.Time(from + _bucket)}" };
        int total = 0;
        for (int k = 0; k < _ids.Length; k++)
        {
            if (_counts[h, k] == 0) continue;
            total += _counts[h, k];
            lines.Add($"  [{_ids[k]}] {EventCatalog.Get(_ids[k]).Korean}: {_counts[h, k]:N0}");
        }
        lines.Insert(1, $"합계: {total:N0}");
        _tip.SetToolTip(this, string.Join("\n", lines));
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hover = -1;
        Invalidate();
    }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        int h = HitTest(e.Location);
        if (h < 0) return;
        var from = _start + TimeSpan.FromTicks(_bucket.Ticks * h);
        BucketClicked?.Invoke(this, (from, from + _bucket));
    }
}
