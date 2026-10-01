using System.Drawing.Drawing2D;

namespace SysmonAnalyzer.Controls;

public sealed record ChartItem(string Label, double Value, object? Tag = null, Color? Color = null);

/// <summary>제목 + 가로 막대 차트. 항목 클릭 시 ItemClicked 이벤트.</summary>
public sealed class BarChart : Control
{
    private List<ChartItem> _items = new();
    private int _hover = -1;
    private readonly ToolTip _tip = new();
    private string _lastTip = "";

    public string Title { get; set; } = "";
    public string Subtitle { get; set; } = "";
    public Color BarColor { get; set; } = Ui.Accent;
    public int MaxItems { get; set; } = 10;

    public event EventHandler<ChartItem>? ItemClicked;

    public BarChart()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Ui.Surface;
        Font = new Font(Ui.FontName, 9f);
    }

    public void SetItems(IEnumerable<ChartItem> items)
    {
        _items = items.Take(MaxItems).ToList();
        _hover = -1;
        Invalidate();
    }

    private int HeaderHeight => Ui.S(this, string.IsNullOrEmpty(Subtitle) ? 32 : 46);

    private RectangleF RowRect(int i, out float rowH)
    {
        float top = HeaderHeight;
        float avail = Height - top - Ui.S(this, 8);
        rowH = Math.Min(Ui.S(this, 26), avail / Math.Max(1, MaxItems));
        return new RectangleF(0, top + i * rowH, Width, rowH);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        float s = Ui.Scale(this);

        using (var pen = new Pen(Ui.Border))
            g.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);

        using var titleFont = Ui.F(10f, FontStyle.Bold);
        using var textBrush = new SolidBrush(Ui.Text);
        using var mutedBrush = new SolidBrush(Ui.Muted);
        g.DrawString(Title, titleFont, textBrush, 10 * s, 8 * s);
        if (!string.IsNullOrEmpty(Subtitle))
            g.DrawString(Subtitle, Font, mutedBrush, 10 * s, 27 * s);

        if (_items.Count == 0)
        {
            var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("데이터 없음", Font, mutedBrush, new RectangleF(0, HeaderHeight, Width, Height - HeaderHeight), sf);
            return;
        }

        double max = Math.Max(1, _items.Max(i => i.Value));
        float labelW = Math.Min(Width * 0.42f, 230 * s);
        float valueW = 64 * s;
        float barX = 10 * s + labelW + 6 * s;
        float barMaxW = Math.Max(10, Width - barX - valueW - 10 * s);
        var fmtLeft = new StringFormat { LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisPath, FormatFlags = StringFormatFlags.NoWrap };
        var fmtRight = new StringFormat { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Far };

        for (int i = 0; i < _items.Count; i++)
        {
            var item = _items[i];
            var row = RowRect(i, out float rowH);
            if (i == _hover)
            {
                using var hb = new SolidBrush(Ui.AccentSoft);
                g.FillRectangle(hb, 1, row.Y, Width - 2, rowH);
            }
            g.DrawString(item.Label, Font, textBrush, new RectangleF(10 * s, row.Y, labelW, rowH), fmtLeft);

            float bw = (float)(item.Value / max * barMaxW);
            var bar = new RectangleF(barX, row.Y + rowH * 0.22f, Math.Max(2, bw), rowH * 0.56f);
            using (var path = Ui.RoundRect(bar, 3 * s))
            using (var bb = new SolidBrush(item.Color ?? BarColor))
                g.FillPath(bb, path);

            g.DrawString(item.Value.ToString("N0"), Font, mutedBrush,
                new RectangleF(Width - valueW - 10 * s, row.Y, valueW, rowH), fmtRight);
        }
    }

    private int HitTest(Point p)
    {
        for (int i = 0; i < _items.Count; i++)
            if (RowRect(i, out _).Contains(p)) return i;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int h = HitTest(e.Location);
        if (h != _hover)
        {
            _hover = h;
            Cursor = h >= 0 && ItemClicked != null ? Cursors.Hand : Cursors.Default;
            Invalidate();
        }
        var tip = h >= 0 ? $"{_items[h].Label}\n{_items[h].Value:N0}" : "";
        if (tip != _lastTip)
        {
            _lastTip = tip;
            _tip.SetToolTip(this, tip);
        }
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
        if (h >= 0) ItemClicked?.Invoke(this, _items[h]);
    }
}
