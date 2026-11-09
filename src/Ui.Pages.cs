namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.Drawing.Drawing2D;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Windows.Forms;

    public interface IMeasured
    {
        int Measure(int width);
    }

    public static class Draw
    {
        public const TextFormatFlags Line = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding;
        public const TextFormatFlags Wrap = TextFormatFlags.NoPrefix | TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.NoPadding;

        public static Size Measure(string s, Font f)
        {
            if (string.IsNullOrEmpty(s)) return new Size(0, f.Height);
            return TextRenderer.MeasureText(s, f, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
        }

        public static int WrapHeight(string s, Font f, int width)
        {
            if (string.IsNullOrEmpty(s) || width <= 0) return 0;
            return TextRenderer.MeasureText(s, f, new Size(width, int.MaxValue), Wrap).Height;
        }

        public static void Text(Graphics g, string s, Font f, Rectangle r, Color c, TextFormatFlags flags)
        {
            if (string.IsNullOrEmpty(s) || r.Width <= 0 || r.Height <= 0) return;
            TextRenderer.DrawText(g, s, f, r, c, flags);
        }

        public static void Card(Graphics g, Rectangle bounds, Theme t)
        {
            RectangleF r = new RectangleF(0.5f, 0.5f, bounds.Width - 1.5f, bounds.Height - 1.5f);
            Shapes.Fill(g, r, Dpi.S(7), t.Card);
            Shapes.Stroke(g, r, Dpi.S(7), t.Divider, 1f);
        }

        public static void Glyph(Graphics g, string glyph, Rectangle r, Color c)
        {
            if (Fonts.Icons == null || string.IsNullOrEmpty(glyph)) return;
            TextRenderer.DrawText(g, glyph, Fonts.Icons, r, c, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }

        // The PolicyVice mark, drawn from the same shapes as the icon (art/icons.py): policy lines and a shield with a check.
        public static void Mark(Graphics g, RectangleF r)
        {
            GraphicsState st = g.Save();
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            float k = Math.Min(r.Width, r.Height) / 1024f;
            g.TranslateTransform(r.X, r.Y);
            g.ScaleTransform(k, k);
            float w = 40f;
            using (GraphicsPath tile = Shapes.Round(new RectangleF(20, 20, 984, 984), 150))
            using (SolidBrush navy = new SolidBrush(Theme.Hex(0x011133)))
                g.FillPath(navy, tile);
            using (Pen cyan = new Pen(Theme.Hex(0x00EEFE), w))
            using (Pen pink = new Pen(Theme.Hex(0xFF199A), w))
            using (GraphicsPath shield = new GraphicsPath())
            {
                cyan.StartCap = cyan.EndCap = LineCap.Round;
                cyan.LineJoin = pink.LineJoin = LineJoin.Round;
                g.DrawLine(cyan, 155 + w / 2, 358, 420, 358);
                g.DrawLine(cyan, 155 + w / 2, 483, 390, 483);
                g.DrawLine(cyan, 155 + w / 2, 608, 340, 608);
                shield.AddLine(662, 262, 836, 324);
                shield.AddLine(836, 324, 836, 476);
                shield.AddBezier(836, 476, 836, 598, 758, 676, 662, 722);
                shield.AddBezier(662, 722, 566, 676, 488, 598, 488, 476);
                shield.AddLine(488, 476, 488, 324);
                shield.CloseFigure();
                g.DrawPath(pink, shield);
                g.DrawLines(cyan, new PointF[] { new PointF(588, 492), new PointF(642, 546), new PointF(744, 442) });
            }
            g.Restore(st);
        }

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        public static void TitleBar(IntPtr h, Theme t)
        {
            try
            {
                int dark = t.IsDark ? 1 : 0;
                DwmSetWindowAttribute(h, 20, ref dark, 4);
            }
            catch (Exception) { }
        }
    }

    public sealed class Toggle : FlatControl
    {
        bool on;
        public event EventHandler Changed;

        public Toggle()
        {
            TabStop = true;
            Cursor = Cursors.Hand;
            Size = new Size(Dpi.S(96), Dpi.S(32));
        }

        public bool On
        {
            get { return on; }
            set
            {
                if (on == value) return;
                on = value;
                Invalidate();
                if (Changed != null) Changed(this, EventArgs.Empty);
            }
        }

        protected override void OnClick(EventArgs e)
        {
            On = !On;
            base.OnClick(e);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Space) { e.Handled = true; On = !On; }
            base.OnKeyDown(e);
        }

        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : T.Card);
            int w = Dpi.S(40), h = Dpi.S(20);
            RectangleF track = new RectangleF(Width - w - Dpi.S(2), (Height - h) / 2f, w, h);
            string text = on ? "On" : "Off";
            int tw = Draw.Measure(text, Fonts.Ui).Width + 2;
            Draw.Text(g, text, Fonts.Ui, new Rectangle((int)track.X - Dpi.S(12) - tw, 0, tw, Height), T.Text, Draw.Line);
            float d = hover ? Dpi.S(14) : Dpi.S(12);
            if (on)
            {
                Shapes.Fill(g, track, h / 2f, hover ? T.AccentHover : T.Accent);
                Shapes.Fill(g, new RectangleF(track.Right - h / 2f - d / 2f, track.Y + (h - d) / 2f, d, d), d / 2f, T.OnAccent);
            }
            else
            {
                Shapes.Stroke(g, track, h / 2f, T.Text2, 1f);
                Shapes.Fill(g, new RectangleF(track.X + h / 2f - d / 2f, track.Y + (h - d) / 2f, d, d), d / 2f, T.Text2);
            }
            if (Focused && ShowFocusCues) Shapes.Stroke(g, RectangleF.Inflate(track, 3, 3), h / 2f + 3, T.Text, 2f);
        }
    }

    public sealed class Segmented : FlatControl
    {
        readonly string[] items;
        int sel, hot = -1;
        public event EventHandler Changed;

        public Segmented(params string[] items)
        {
            this.items = items;
            TabStop = true;
            Cursor = Cursors.Hand;
            Height = Dpi.S(32);
            int w = Dpi.S(6);
            for (int i = 0; i < items.Length; i++) w += ItemW(i);
            Width = w;
        }

        int ItemW(int i)
        {
            return Draw.Measure(items[i], Fonts.UiSemibold).Width + Dpi.S(28);
        }

        public int Selected
        {
            get { return sel; }
            set
            {
                if (value < 0 || value >= items.Length || value == sel) return;
                sel = value;
                Invalidate();
                if (Changed != null) Changed(this, EventArgs.Empty);
            }
        }

        int IndexAt(int x)
        {
            int px = Dpi.S(3);
            for (int i = 0; i < items.Length; i++)
            {
                int w = ItemW(i);
                if (x >= px && x < px + w) return i;
                px += w;
            }
            return -1;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            int i = IndexAt(e.X);
            if (i != hot) { hot = i; Invalidate(); }
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            hot = -1;
            base.OnMouseLeave(e);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
            int i = IndexAt(e.X);
            if (i >= 0 && e.Button == MouseButtons.Left) Selected = i;
        }

        protected override bool IsInputKey(Keys keyData)
        {
            Keys k = keyData & Keys.KeyCode;
            return k == Keys.Left || k == Keys.Right || base.IsInputKey(keyData);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Left) { Selected = Math.Max(0, sel - 1); e.Handled = true; }
            else if (e.KeyCode == Keys.Right) { Selected = Math.Min(items.Length - 1, sel + 1); e.Handled = true; }
            base.OnKeyDown(e);
        }

        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : T.Card);
            RectangleF outer = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Shapes.Fill(g, outer, Dpi.S(5), T.Field);
            Shapes.Stroke(g, outer, Dpi.S(5), T.FieldStroke, 1f);
            int x = Dpi.S(3);
            for (int i = 0; i < items.Length; i++)
            {
                int w = ItemW(i);
                RectangleF r = new RectangleF(x, Dpi.S(3), w, Height - Dpi.S(6));
                if (i == sel)
                {
                    Shapes.Fill(g, r, Dpi.S(4), Theme.Mix(T.Field, T.Accent, T.IsDark ? 0.22f : 0.13f));
                    float pw = Dpi.S(16);
                    Shapes.Fill(g, new RectangleF(r.X + (w - pw) / 2f, r.Bottom - Dpi.S(3), pw, Dpi.S(3)), 1.5f, T.Accent);
                }
                else if (i == hot) Shapes.Fill(g, r, Dpi.S(4), T.Hover);
                Draw.Text(g, items[i], i == sel ? Fonts.UiSemibold : Fonts.Ui, Rectangle.Round(r), i == sel ? T.Accent : T.Text, Draw.Line | TextFormatFlags.HorizontalCenter);
                x += w;
            }
            if (Focused && ShowFocusCues) Shapes.Stroke(g, outer, Dpi.S(5), T.Text, 2f);
        }
    }

    // Lays out its children side by side, right to left in the order given.
    public sealed class ButtonStrip : Panel, IThemed
    {
        public ButtonStrip(params Control[] items)
        {
            int x = 0, h = 0;
            foreach (Control c in items)
            {
                c.Location = new Point(x, 0);
                x += c.Width + Dpi.S(8);
                h = Math.Max(h, c.Height);
                Controls.Add(c);
            }
            Size = new Size(Math.Max(0, x - Dpi.S(8)), h);
        }

        public void Fit()
        {
            int x = 0;
            foreach (Control c in Controls)
            {
                if (!c.Visible) continue;
                c.Location = new Point(x, (Height - c.Height) / 2);
                x += c.Width + Dpi.S(8);
            }
            Width = Math.Max(0, x - Dpi.S(8));
        }

        public void ApplyTheme(Theme t)
        {
            BackColor = t.Card;
            foreach (Control c in Controls)
            {
                IThemed th = c as IThemed;
                if (th != null) th.ApplyTheme(t);
                else { c.BackColor = t.Field; c.ForeColor = t.Text; }
            }
        }
    }

    public sealed class SettingRow : Panel, IThemed, IMeasured
    {
        Theme theme = Theme.Light();
        public string Glyph, Title, Desc, Value;
        public bool MonoDesc;
        public readonly Control Accessory;

        public SettingRow(string glyph, string title, string desc, Control right)
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Glyph = glyph;
            Title = title;
            Desc = desc;
            Accessory = right;
            if (right != null) Controls.Add(right);
        }

        int TextX()
        {
            return Fonts.Icons != null && !string.IsNullOrEmpty(Glyph) ? Dpi.S(56) : Dpi.S(20);
        }

        int RightW(int width)
        {
            if (Accessory != null) return Accessory.Width + Dpi.S(32);
            if (!string.IsNullOrEmpty(Value)) return Math.Min(Draw.Measure(Value, Fonts.Ui).Width + 2, width / 2) + Dpi.S(20);
            return Dpi.S(16);
        }

        Font DescFont
        {
            get { return MonoDesc ? Fonts.MonoSmall : Fonts.Small; }
        }

        public int Measure(int width)
        {
            int tw = Math.Max(Dpi.S(80), width - TextX() - RightW(width));
            int h = Dpi.S(14) + Fonts.Ui.Height;
            if (!string.IsNullOrEmpty(Desc)) h += Dpi.S(2) + Draw.WrapHeight(Desc, DescFont, tw);
            h += Dpi.S(14);
            int min = Accessory != null ? Accessory.Height + Dpi.S(24) : Dpi.S(56);
            return Math.Max(min, h);
        }

        public void ApplyTheme(Theme t)
        {
            theme = t;
            BackColor = t.Card;
            IThemed th = Accessory as IThemed;
            if (th != null) th.ApplyTheme(t);
            else if (Accessory != null) { Accessory.BackColor = t.Field; Accessory.ForeColor = t.Text; }
            Invalidate();
        }

        protected override void OnLayout(LayoutEventArgs levent)
        {
            base.OnLayout(levent);
            if (Accessory != null) Accessory.Location = new Point(Width - Dpi.S(16) - Accessory.Width, (Height - Accessory.Height) / 2);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : theme.Bg);
            Draw.Card(g, ClientRectangle, theme);
            int s = Dpi.S(20);
            Draw.Glyph(g, Glyph, new Rectangle(Dpi.S(18), (Height - s) / 2, s, s), theme.Text2);
            int tx = TextX();
            int tw = Math.Max(Dpi.S(80), Width - tx - RightW(Width));
            int th = Fonts.Ui.Height;
            int dh = string.IsNullOrEmpty(Desc) ? 0 : Draw.WrapHeight(Desc, DescFont, tw);
            int block = th + (dh > 0 ? Dpi.S(2) + dh : 0);
            int y = (Height - block) / 2;
            Draw.Text(g, Title, Fonts.Ui, new Rectangle(tx, y, tw, th), theme.Text, Draw.Line);
            if (dh > 0) Draw.Text(g, Desc, DescFont, new Rectangle(tx, y + th + Dpi.S(2), tw, dh + 2), theme.Text2, Draw.Wrap);
            if (Accessory == null && !string.IsNullOrEmpty(Value))
            {
                int vw = RightW(Width) - Dpi.S(20);
                Draw.Text(g, Value, Fonts.Ui, new Rectangle(Width - Dpi.S(20) - vw, 0, vw, Height), theme.Text2, Draw.Line | TextFormatFlags.Right);
            }
        }
    }

    public sealed class SectionTitle : FlatControl, IMeasured
    {
        public SectionTitle(string text)
        {
            Text = text;
            TabStop = false;
            SetStyle(ControlStyles.Selectable, false);
            Height = Dpi.S(34);
        }

        public int Measure(int width)
        {
            return Height;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(T.Bg);
            Draw.Text(e.Graphics, Text, Fonts.UiSemibold, new Rectangle(Dpi.S(2), Height - Fonts.UiSemibold.Height - Dpi.S(8), Width, Fonts.UiSemibold.Height + 2), T.Text, Draw.Line);
        }
    }

    public sealed class AboutHero : FlatControl, IMeasured
    {
        public string Version = "", Detail = "", Developer = "", Blurb = "", License = "";

        public AboutHero()
        {
            TabStop = false;
            SetStyle(ControlStyles.Selectable, false);
        }

        int TextX
        {
            get { return Dpi.S(112); }
        }

        public int Measure(int width)
        {
            int bh = Draw.WrapHeight(Blurb, Fonts.Ui, Math.Max(Dpi.S(100), width - TextX - Dpi.S(24)));
            return Math.Max(Dpi.S(128), Dpi.S(22) + Fonts.Title.Height + Dpi.S(4) + Fonts.Ui.Height * 2 + Dpi.S(14) + bh + Dpi.S(10) + Fonts.Small.Height + Dpi.S(22));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(T.Bg);
            Draw.Card(g, ClientRectangle, T);
            Draw.Mark(g, new RectangleF(Dpi.S(24), Dpi.S(24), Dpi.S(68), Dpi.S(68)));
            int tx = TextX, tw = Width - tx - Dpi.S(24);
            int y = Dpi.S(22);
            Draw.Text(g, "PolicyVice", Fonts.Title, new Rectangle(tx, y, tw, Fonts.Title.Height), T.Text, Draw.Line);
            y += Fonts.Title.Height + Dpi.S(4);
            Draw.Text(g, Version + "   ·   " + Detail, Fonts.Ui, new Rectangle(tx, y, tw, Fonts.Ui.Height), T.Text2, Draw.Line);
            y += Fonts.Ui.Height;
            string lead = "Developed by";
            int lw = Draw.Measure(lead, Fonts.Ui).Width + Dpi.S(5);
            Draw.Text(g, lead, Fonts.Ui, new Rectangle(tx, y, lw + 2, Fonts.Ui.Height), T.Text2, Draw.Line);
            Draw.Text(g, Developer, Fonts.UiSemibold, new Rectangle(tx + lw, y, Math.Max(0, tw - lw), Fonts.Ui.Height), T.Text, Draw.Line);
            y += Fonts.Ui.Height + Dpi.S(14);
            int bh = Draw.WrapHeight(Blurb, Fonts.Ui, tw);
            Draw.Text(g, Blurb, Fonts.Ui, new Rectangle(tx, y, tw, bh + 2), T.Text, Draw.Wrap);
            y += bh + Dpi.S(10);
            Draw.Text(g, License, Fonts.Small, new Rectangle(tx, y, tw, Fonts.Small.Height + 2), T.Text3, Draw.Line);
        }
    }

    // Two columns: a key (a shortcut or a command) and what it does.
    public sealed class KeyTable : FlatControl, IMeasured
    {
        readonly string[][] rows;
        readonly bool mono;

        public KeyTable(bool monoKeys, params string[][] rows)
        {
            this.rows = rows;
            mono = monoKeys;
            TabStop = false;
            SetStyle(ControlStyles.Selectable, false);
        }

        Font KeyFont
        {
            get { return mono ? Fonts.Mono : Fonts.SmallSemibold; }
        }

        int KeyW(int width)
        {
            int w = 0;
            foreach (string[] r in rows) w = Math.Max(w, Draw.Measure(r[0], KeyFont).Width + Dpi.S(16));
            return Math.Min(w, width * 3 / 5);
        }

        int RowH(string[] r, int width)
        {
            int dw = Math.Max(Dpi.S(60), width - KeyW(width) - Dpi.S(64));
            return Math.Max(Dpi.S(34), Draw.WrapHeight(r[1], Fonts.Ui, dw) + Dpi.S(14));
        }

        public string AsText()
        {
            StringBuilder b = new StringBuilder();
            foreach (string[] r in rows) b.Append(r[0].PadRight(42)).Append(r[1]).Append("\r\n");
            return b.ToString();
        }

        public int Measure(int width)
        {
            int h = Dpi.S(12);
            foreach (string[] r in rows) h += RowH(r, width);
            return h;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(T.Bg);
            Draw.Card(g, ClientRectangle, T);
            int kw = KeyW(Width);
            int y = Dpi.S(6);
            int dx = Dpi.S(20) + kw + Dpi.S(20);
            foreach (string[] r in rows)
            {
                int h = RowH(r, Width);
                int kh = KeyFont.Height + Dpi.S(6);
                Rectangle key = new Rectangle(Dpi.S(20), y + (h - kh) / 2, Math.Min(kw, Draw.Measure(r[0], KeyFont).Width + Dpi.S(16)), kh);
                Shapes.Fill(g, key, Dpi.S(4), T.CardAlt);
                Shapes.Stroke(g, key, Dpi.S(4), T.Divider, 1f);
                Draw.Text(g, r[0], KeyFont, key, T.Text, Draw.Line | TextFormatFlags.HorizontalCenter);
                int dw = Math.Max(0, Width - dx - Dpi.S(20));
                int dh = Draw.WrapHeight(r[1], Fonts.Ui, dw);
                Draw.Text(g, r[1], Fonts.Ui, new Rectangle(dx, y + (h - dh) / 2, dw, dh + 2), T.Text2, Draw.Wrap);
                y += h;
            }
        }
    }

    // A themed dialog with a scrolling column of cards and a footer, like the settings pages in LogVice.
    public class PageForm : Form
    {
        protected Theme theme;
        readonly Panel scroll = new Panel();
        readonly Panel col = new Panel();
        protected readonly Panel footer = new Panel();
        readonly List<Control> items = new List<Control>();
        protected readonly FlatButton bClose = new FlatButton("Close", null);

        public PageForm(string title, Theme t)
        {
            theme = t;
            Text = title;
            Font = Fonts.Ui;
            Icon = Program.AppIcon();
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            MinimizeBox = false;
            MaximizeBox = false;
            KeyPreview = true;
            Size = new Size(Dpi.S(780), Dpi.S(660));
            MinimumSize = new Size(Dpi.S(560), Dpi.S(420));
            BackColor = t.Bg;
            ForeColor = t.Text;
            scroll.Dock = DockStyle.Fill;
            scroll.AutoScroll = true;
            scroll.BackColor = t.Bg;
            col.BackColor = t.Bg;
            scroll.Controls.Add(col);
            scroll.Resize += delegate { Relayout(); };
            footer.Dock = DockStyle.Bottom;
            footer.Height = Dpi.S(60);
            footer.Padding = new Padding(Dpi.S(24), Dpi.S(14), Dpi.S(24), Dpi.S(14));
            footer.BackColor = t.Bg;
            bClose.Primary = true;
            bClose.Width = Math.Max(bClose.Width, Dpi.S(96));
            bClose.Dock = DockStyle.Right;
            bClose.Click += delegate { Close(); };
            bClose.ApplyTheme(t);
            footer.Controls.Add(bClose);
            Controls.Add(scroll);
            Controls.Add(footer);
            HandleCreated += delegate { Draw.TitleBar(Handle, theme); };
            HookWheel(scroll);
        }

        public void Retheme(Theme t)
        {
            theme = t;
            BackColor = scroll.BackColor = col.BackColor = footer.BackColor = t.Bg;
            ForeColor = t.Text;
            foreach (Control c in items) { IThemed th = c as IThemed; if (th != null) th.ApplyTheme(t); }
            foreach (Control c in footer.Controls) { IThemed th = c as IThemed; if (th != null) th.ApplyTheme(t); }
            if (IsHandleCreated) Draw.TitleBar(Handle, t);
            Invalidate(true);
        }

        protected void Add(Control c)
        {
            items.Add(c);
            col.Controls.Add(c);
            IThemed th = c as IThemed;
            if (th != null) th.ApplyTheme(theme);
            HookWheel(c);
        }

        protected void Relayout()
        {
            int pad = Dpi.S(24);
            int w = Math.Max(Dpi.S(240), scroll.ClientSize.Width - pad * 2);
            int y = Dpi.S(8);
            col.SuspendLayout();
            foreach (Control c in items)
            {
                IMeasured m = c as IMeasured;
                int h = m != null ? m.Measure(w) : c.Height;
                if (c is SectionTitle && y > Dpi.S(8)) y += Dpi.S(10);
                c.SetBounds(0, y, w, h);
                y += h + (c is SectionTitle ? Dpi.S(2) : Dpi.S(6));
            }
            col.ResumeLayout(true);
            col.SetBounds(pad, scroll.AutoScrollPosition.Y, w, y + Dpi.S(16));
            foreach (Control c in items) c.Invalidate();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Relayout();
        }

        void HookWheel(Control c)
        {
            if (c is NumericUpDown) return;
            c.MouseWheel += delegate (object s, MouseEventArgs e)
            {
                if (s == scroll) return;
                HandledMouseEventArgs h = e as HandledMouseEventArgs;
                if (h != null) h.Handled = true;
                int y = -scroll.AutoScrollPosition.Y - e.Delta / 120 * Dpi.S(80);
                scroll.AutoScrollPosition = new Point(0, Math.Max(0, y));
            };
            foreach (Control k in c.Controls) HookWheel(k);
        }

        protected FlatButton SmallButton(string text, EventHandler click)
        {
            FlatButton b = new FlatButton(text, null);
            b.Compact = true;
            b.AutoWidth();
            b.Width += Dpi.S(8);
            b.Click += Safe.Wrap(click);
            b.ApplyTheme(theme);
            return b;
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.Escape)
            {
                Close();
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }
    }

    public sealed class SettingsDialog : PageForm
    {
        public event EventHandler ThemeChanged;
        public bool DaysChanged, RestartRequested;
        readonly SettingRow logViceRow;

        public SettingsDialog(Theme t) : base("PolicyVice settings", t)
        {
            string[] themes = { "System", "Light", "Dark", "Vice" };
            Segmented segTheme = new Segmented(themes);
            int ti = Array.IndexOf(themes, Prefs.Get("Theme", "System"));
            segTheme.Selected = ti < 0 ? 0 : ti;
            segTheme.Changed += Safe.Wrap(delegate
            {
                Prefs.Set("Theme", themes[segTheme.Selected]);
                Retheme(Theme.Named(themes[segTheme.Selected]));
                if (ThemeChanged != null) ThemeChanged(this, EventArgs.Empty);
            });

            NumericUpDown days = new NumericUpDown();
            days.Minimum = 1;
            days.Maximum = 90;
            days.Value = Prefs.GetInt("EventDays", 7, 1, 90);
            days.Width = Dpi.S(80);
            days.Font = Fonts.Ui;
            days.BorderStyle = BorderStyle.FixedSingle;
            days.TextAlign = HorizontalAlignment.Right;
            days.ValueChanged += Safe.Wrap(delegate
            {
                Prefs.Set("EventDays", ((int)days.Value).ToString(System.Globalization.CultureInfo.InvariantCulture));
                DaysChanged = true;
            });

            Toggle watch = new Toggle();
            watch.On = Prefs.GetBool("WatchAfterSync", true);
            watch.Changed += Safe.Wrap(delegate { Prefs.SetBool("WatchAfterSync", watch.On); });

            FlatButton bBrowse = SmallButton("Browse", delegate { Browse(); });
            FlatButton bClear = SmallButton("Clear", delegate
            {
                Prefs.Set("LogVicePath", null);
                UpdateLogVice();
            });
            logViceRow = new SettingRow(Glyphs2.Folder, "LogVice", "", new ButtonStrip(bBrowse, bClear));
            UpdateLogVice();

            Add(new SectionTitle("Appearance"));
            Add(new SettingRow(Glyphs2.Palette, "Theme", "Light, Dark or Vice, or follow the Windows app mode. The same themes as LogVice.", segTheme));
            Add(new SectionTitle("Reading the device"));
            Add(new SettingRow(Glyphs2.Calendar, "Days of MDM events", "How many days of errors and warnings to read from the DeviceManagement Admin event log, from 1 to 90. Applies the next time the device is read.", days));
            if (Program.IsAdmin)
            {
                SettingRow admin = new SettingRow(Glyphs.Shield, "Administrator rights", "PolicyVice is running as administrator, so it can read every policy key, Resultant Set of Policy and start a sync.", null);
                admin.Value = "On";
                Add(admin);
            }
            else
            {
                FlatButton bAdmin = SmallButton("Restart as administrator", delegate
                {
                    RestartRequested = true;
                    Close();
                });
                Add(new SettingRow(Glyphs.Shield, "Administrator rights", "Some keys, Resultant Set of Policy and Sync need administrator rights. Without them more owners show as Unknown.", bAdmin));
            }
            Add(new SectionTitle("Sync"));
            Add(new SettingRow(Glyphs2.Sync, "Start Watch after Sync", "Turn on Watch when a sync starts, so every policy change it brings is recorded on the Changes tab with the MDM events around it.", watch));
            Add(new SectionTitle("LogVice"));
            Add(logViceRow);
            SettingRow store = new SettingRow(Glyphs2.Settings, "Where settings are stored", Prefs.Location, null);
            store.MonoDesc = true;
            Add(new SectionTitle("Data"));
            Add(store);
        }

        void UpdateLogVice()
        {
            string custom = Prefs.Get("LogVicePath", null);
            string found = LogViceLink.Find();
            if (!string.IsNullOrEmpty(custom)) logViceRow.Desc = "Chosen: " + custom + (found == custom ? "" : " (not found)");
            else if (found != null) logViceRow.Desc = "Found: " + found;
            else logViceRow.Desc = "Not found. PolicyVice looks for the LogVice MSI install, App Paths and LogVice.exe next to PolicyVice.exe. Browse to choose it.";
            Relayout();
        }

        void Browse()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Filter = "LogVice|LogVice.exe|Programs|*.exe";
                d.Title = "Locate LogVice";
                if (d.ShowDialog(this) != DialogResult.OK) return;
                Prefs.Set("LogVicePath", d.FileName);
            }
            UpdateLogVice();
        }
    }

    public sealed class AboutDialog : PageForm
    {
        public static readonly string[][] CommandLine =
        {
            new string[] { "PolicyVice.exe", "Open the window" },
            new string[] { "PolicyVice.exe <snapshot.json>", "Open a saved snapshot" },
            new string[] { "/snapshot <file.json>", "Save a snapshot of this device" },
            new string[] { "/report <file.html>", "Save an HTML report of this device" },
            new string[] { "/csv <file.csv>", "Save all settings as CSV" },
            new string[] { "/diff <a.json> <b.json>", "Compare two snapshots. Add /out <file.html> for a report" },
            new string[] { "/days <n>", "Days of MDM events to read (default 7)" },
            new string[] { "--demo", "Open the window with sample data" },
        };

        public AboutDialog(Theme t) : base("About PolicyVice", t)
        {
            AboutHero hero = new AboutHero();
            hero.Version = "Version " + Program.Version;
            hero.Detail = "Built " + Program.BuildDate;
            hero.Developer = Program.Developer;
            hero.Blurb = "Shows what policy is set on a Windows device, who set it, and why it failed or disappeared: MDM (Intune) policy, ingested ADMX, Group Policy, the policy registry and Intune apps and scripts. A companion to LogVice.";
            hero.License = "Released under the MIT license.";
            Add(hero);
            Add(new SectionTitle("Command line"));
            KeyTable cli = new KeyTable(true, CommandLine);
            Add(cli);
            Add(new SettingRow(Glyphs.Info, "Exit codes", "0 when done, 1 on an error, and 2 when /snapshot, /report or /csv found conflicts, errors, orphans or unmanaged values. Use Start-Process with -Wait in PowerShell.", null));
            Add(new SectionTitle("Keyboard shortcuts"));
            Add(new KeyTable(false,
                new string[] { "F5", "Read the device again" },
                new string[] { "Ctrl+F", "Search settings" },
                new string[] { "Ctrl+S", "Save a snapshot" },
                new string[] { "Ctrl+E", "Export an HTML report" },
                new string[] { "Ctrl+C", "Copy the selected row" },
                new string[] { "Ctrl+,", "Settings" },
                new string[] { "F1", "This page" },
                new string[] { "Esc", "Clear the search, or close this page" }));
            Add(new SectionTitle("Privacy"));
            Add(new SettingRow(Glyphs.Shield, "PolicyVice only reads", "It writes nothing to the device except its own settings in " + Prefs.Location + " and the files you save. Sync is the one exception: it starts the MDM sync tasks that Windows itself created for each Intune enrollment.", null));

            FlatButton bCopy = new FlatButton("Copy details", Glyphs.Copy);
            bCopy.Dock = DockStyle.Left;
            bCopy.ApplyTheme(t);
            bCopy.Click += Safe.Wrap(delegate
            {
                StringBuilder b = new StringBuilder();
                b.Append("PolicyVice ").Append(Program.Version).Append(" (built ").Append(Program.BuildDate).Append(") by ").Append(Program.Developer).Append("\r\n");
                b.Append("Windows: ").Append(Program.OsVersion()).Append("\r\n");
                b.Append(".NET: ").Append(Environment.Version).Append(Environment.Is64BitProcess ? ", 64-bit" : ", 32-bit").Append("\r\n");
                b.Append("Administrator: ").Append(Program.IsAdmin ? "yes" : "no").Append("\r\n");
                b.Append("Program: ").Append(Program.Location).Append("\r\n\r\n").Append(cli.AsText());
                bCopy.Text = Menus.Copy(b.ToString()) ? "Copied" : "Clipboard busy";
            });
            footer.Controls.Add(bCopy);
        }
    }
}
