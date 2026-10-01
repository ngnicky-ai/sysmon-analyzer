namespace SysmonAnalyzer.Controls;

/// <summary>대시보드 상단 요약 카드.</summary>
public sealed class StatCard : Control
{
    public string Caption { get; set; } = "";
    public string Value { get; set; } = "-";
    public string Note { get; set; } = "";
    public Color AccentColor { get; set; } = Ui.Accent;

    public event EventHandler? CardClicked;

    public StatCard()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Ui.Surface;
        Font = new Font(Ui.FontName, 9f);
    }

    public void Set(string value, string note = "")
    {
        Value = value;
        Note = note;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        float s = Ui.Scale(this);
        using (var pen = new Pen(Ui.Border)) g.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        using (var b = new SolidBrush(AccentColor)) g.FillRectangle(b, 0, 0, 4 * s, Height);

        using var muted = new SolidBrush(Ui.Muted);
        using var text = new SolidBrush(Ui.Text);
        using var big = Ui.F(16f, FontStyle.Bold);
        var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
        g.DrawString(Caption, Font, muted, new RectangleF(12 * s, 8 * s, Width - 16 * s, 18 * s), fmt);
        g.DrawString(Value, big, text, new RectangleF(10 * s, 26 * s, Width - 14 * s, 34 * s), fmt);
        if (!string.IsNullOrEmpty(Note))
            g.DrawString(Note, Font, muted, new RectangleF(12 * s, Height - 24 * s, Width - 16 * s, 18 * s), fmt);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        if (CardClicked != null) Cursor = Cursors.Hand;
    }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        CardClicked?.Invoke(this, EventArgs.Empty);
    }
}
