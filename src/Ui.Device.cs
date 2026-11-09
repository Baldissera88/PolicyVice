namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.Text;
    using System.Windows.Forms;

    // One group of device information: a title and label/value rows.
    public sealed class InfoCard : FlatControl
    {
        public readonly string Group;
        public readonly List<InfoItem> Items = new List<InfoItem>();
        readonly List<Rectangle> rects = new List<Rectangle>();
        int sel = -1, hotRow = -1, laidOut = -1;
        public event EventHandler MenuRequested;

        public InfoCard(string group)
        {
            Group = string.IsNullOrEmpty(group) ? "Other" : group;
            TabStop = true;
        }

        int HeaderH
        {
            get { return Dpi.S(44); }
        }

        int LabelW(int width)
        {
            return Math.Min(Dpi.S(210), Math.Max(Dpi.S(110), width * 2 / 5));
        }

        public int Measure(int width)
        {
            Arrange(width);
            return rects.Count == 0 ? HeaderH : rects[rects.Count - 1].Bottom + Dpi.S(8);
        }

        void Arrange(int width)
        {
            rects.Clear();
            laidOut = width;
            int lw = LabelW(width);
            int vw = Math.Max(Dpi.S(60), width - lw - Dpi.S(48));
            int y = HeaderH;
            foreach (InfoItem i in Items)
            {
                int h = Math.Max(Draw.WrapHeight(i.Label, Fonts.Ui, lw - Dpi.S(8)), Draw.WrapHeight(i.Value, Fonts.Ui, vw));
                h = Math.Max(Dpi.S(32), h + Dpi.S(14));
                rects.Add(new Rectangle(Dpi.S(1), y, width - Dpi.S(2), h));
                y += h;
            }
        }

        public InfoItem Selected
        {
            get { return sel >= 0 && sel < Items.Count ? Items[sel] : null; }
        }

        int RowAt(Point p)
        {
            for (int i = 0; i < rects.Count; i++) if (rects[i].Contains(p)) return i;
            return -1;
        }

        public void ClearSelection()
        {
            if (sel < 0) return;
            sel = -1;
            Invalidate();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            int r = RowAt(e.Location);
            if (r != hotRow) { hotRow = r; Invalidate(); }
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            hotRow = -1;
            base.OnMouseLeave(e);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
            int r = RowAt(e.Location);
            if (r >= 0) sel = r;
            Invalidate();
            if (e.Button == MouseButtons.Right && MenuRequested != null) MenuRequested(this, EventArgs.Empty);
        }

        protected override void OnDoubleClick(EventArgs e)
        {
            base.OnDoubleClick(e);
            if (Selected != null) Menus.Copy(Selected.Value);
        }

        protected override bool IsInputKey(Keys keyData)
        {
            Keys k = keyData & Keys.KeyCode;
            return k == Keys.Up || k == Keys.Down || base.IsInputKey(keyData);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.C)
            {
                Menus.Copy(Selected != null ? Selected.Label + "\t" + Selected.Value : AsText());
                e.Handled = true;
            }
            else if (e.KeyCode == Keys.Down && Items.Count > 0) { sel = Math.Min(Items.Count - 1, sel + 1); Invalidate(); e.Handled = true; }
            else if (e.KeyCode == Keys.Up && Items.Count > 0) { sel = Math.Max(0, sel - 1); Invalidate(); e.Handled = true; }
            base.OnKeyDown(e);
        }

        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

        public string AsText()
        {
            StringBuilder b = new StringBuilder();
            b.Append(Group).Append("\r\n");
            foreach (InfoItem i in Items) b.Append(i.Label).Append('\t').Append(i.Value).Append("\r\n");
            return b.ToString();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : T.Bg);
            if (laidOut != Width) Arrange(Width);
            Draw.Card(g, ClientRectangle, T);
            Draw.Text(g, Group, Fonts.UiSemibold, new Rectangle(Dpi.S(20), 0, Width - Dpi.S(40), HeaderH), T.Text, Draw.Line);
            int lw = LabelW(Width);
            using (Pen p = new Pen(T.Divider))
            {
                for (int i = 0; i < rects.Count && i < Items.Count; i++)
                {
                    Rectangle r = rects[i];
                    if (i == sel || i == hotRow)
                        using (SolidBrush b = new SolidBrush(i == sel && Focused ? T.AccentSoft : T.Hover)) g.FillRectangle(b, r);
                    g.DrawLine(p, Dpi.S(20), r.Top, Width - Dpi.S(20), r.Top);
                    int lh = Draw.WrapHeight(Items[i].Label, Fonts.Ui, lw - Dpi.S(8));
                    Draw.Text(g, Items[i].Label, Fonts.Ui, new Rectangle(Dpi.S(20), r.Top + (r.Height - lh) / 2, lw - Dpi.S(8), lh + 2), T.Text2, Draw.Wrap);
                    int vx = Dpi.S(20) + lw + Dpi.S(8), vw = Math.Max(Dpi.S(60), Width - vx - Dpi.S(20));
                    int vh = Draw.WrapHeight(Items[i].Value, Fonts.Ui, vw);
                    Draw.Text(g, Items[i].Value, Fonts.Ui, new Rectangle(vx, r.Top + (r.Height - vh) / 2, vw, vh + 2), T.Text, Draw.Wrap);
                }
            }
        }
    }

    // The Device tab: device information grouped in cards, in two columns when there is room.
    public sealed class DeviceView : Panel, IThemed
    {
        Theme theme = Theme.Light();
        readonly Panel top = new Panel();
        readonly Label caption = new Label();
        readonly FlatButton bCopy = new FlatButton("Copy all", Glyphs.Copy);
        readonly Panel scroll = new Panel();
        readonly Label empty = new Label();
        readonly List<InfoCard> cards = new List<InfoCard>();
        readonly ContextMenuStrip menu = new ContextMenuStrip();

        public DeviceView()
        {
            Dock = DockStyle.Fill;
            top.Dock = DockStyle.Top;
            top.Height = Dpi.S(44);
            caption.Dock = DockStyle.Fill;
            caption.TextAlign = ContentAlignment.MiddleLeft;
            caption.Font = Fonts.UiSemibold;
            caption.AutoEllipsis = true;
            bCopy.Dock = DockStyle.Right;
            bCopy.Click += Safe.Wrap(delegate { Menus.Copy(AsText()); });
            top.Controls.Add(caption);
            top.Controls.Add(bCopy);
            scroll.Dock = DockStyle.Fill;
            scroll.AutoScroll = true;
            scroll.Resize += delegate { Relayout(); };
            empty.Dock = DockStyle.Fill;
            empty.TextAlign = ContentAlignment.MiddleCenter;
            empty.Text = "No device information was read.";
            empty.Visible = false;
            Controls.Add(scroll);
            Controls.Add(empty);
            Controls.Add(top);
        }

        public string AsText()
        {
            StringBuilder b = new StringBuilder();
            foreach (InfoCard c in cards) b.Append(c.AsText()).Append("\r\n");
            return b.ToString().TrimEnd() + "\r\n";
        }

        public void SetItems(List<InfoItem> items, string title)
        {
            scroll.SuspendLayout();
            foreach (InfoCard c in cards)
            {
                scroll.Controls.Remove(c);
                c.Dispose();
            }
            cards.Clear();
            Dictionary<string, InfoCard> byGroup = new Dictionary<string, InfoCard>(StringComparer.OrdinalIgnoreCase);
            foreach (InfoItem i in items ?? new List<InfoItem>())
            {
                if (i == null) continue;
                string gname = string.IsNullOrEmpty(i.Group) ? "Other" : i.Group;
                InfoCard c;
                if (!byGroup.TryGetValue(gname, out c))
                {
                    c = new InfoCard(gname);
                    c.MenuRequested += delegate (object s, EventArgs e) { ShowMenu((InfoCard)s); };
                    c.GotFocus += delegate (object s, EventArgs e) { foreach (InfoCard o in cards) if (o != s) o.ClearSelection(); };
                    c.MouseWheel += OnCardWheel;
                    c.ApplyTheme(theme);
                    byGroup[gname] = c;
                    cards.Add(c);
                    scroll.Controls.Add(c);
                }
                c.Items.Add(i);
            }
            scroll.ResumeLayout(false);
            int n = 0;
            foreach (InfoCard c in cards) n += c.Items.Count;
            caption.Text = title;
            empty.Visible = n == 0;
            scroll.Visible = n > 0;
            bCopy.Visible = n > 0;
            scroll.AutoScrollPosition = new Point(0, 0);
            Relayout();
        }

        void OnCardWheel(object sender, MouseEventArgs e)
        {
            HandledMouseEventArgs h = e as HandledMouseEventArgs;
            if (h != null) h.Handled = true;
            int y = -scroll.AutoScrollPosition.Y - e.Delta / 120 * Dpi.S(80);
            scroll.AutoScrollPosition = new Point(0, Math.Max(0, y));
        }

        void ShowMenu(InfoCard c)
        {
            Menus.Prepare(menu, theme);
            InfoItem i = c.Selected;
            if (i != null)
            {
                Menus.Add(menu, "Copy value", delegate { Menus.Copy(i.Value); });
                Menus.Add(menu, "Copy row  (Ctrl+C)", delegate { Menus.Copy(i.Label + "\t" + i.Value); });
            }
            Menus.Add(menu, "Copy " + c.Group, delegate { Menus.Copy(c.AsText()); });
            Menus.Add(menu, "Copy all", delegate { Menus.Copy(AsText()); });
            menu.Show(c, c.PointToClient(Cursor.Position));
        }

        void Relayout()
        {
            if (cards.Count == 0) return;
            int gap = Dpi.S(12);
            // Always leave room for the vertical scroll bar, so the cards never cause a horizontal one.
            int avail = scroll.Width - SystemInformation.VerticalScrollBarWidth - Dpi.S(6);
            int cols = avail >= Dpi.S(940) && cards.Count > 1 ? 2 : 1;
            int w = cols == 2 ? (avail - gap) / 2 : avail;
            if (w < Dpi.S(200)) return;
            int[] y = new int[cols];
            int oy = scroll.AutoScrollPosition.Y;
            scroll.SuspendLayout();
            foreach (InfoCard c in cards)
            {
                int k = cols == 2 && y[1] < y[0] ? 1 : 0;
                int h = c.Measure(w);
                c.SetBounds(k * (w + gap), y[k] + oy, w, h);
                y[k] += h + gap;
            }
            scroll.ResumeLayout(true);
            foreach (InfoCard c in cards) c.Invalidate();
        }

        public void ApplyTheme(Theme t)
        {
            theme = t;
            BackColor = t.Bg;
            top.BackColor = t.Bg;
            scroll.BackColor = t.Bg;
            caption.ForeColor = t.Text;
            empty.ForeColor = t.Text3;
            empty.BackColor = t.Bg;
            bCopy.ApplyTheme(t);
            foreach (InfoCard c in cards) c.ApplyTheme(t);
        }
    }
}
