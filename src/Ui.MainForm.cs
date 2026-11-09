namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using System.Windows.Forms;

    public sealed class MainForm : Form
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        const int TabSettings = 0, TabIntune = 1, TabEvents = 2, TabDevice = 3, TabEnroll = 4, TabAdmx = 5, TabChanges = 6, TabRegistry = 7, TabDenied = 8;

        Theme theme;
        Snapshot snap;
        string snapFile;
        bool demo, busy, pending, pendingWatch, syncing;
        readonly BusyBar busyBar = new BusyBar();

        readonly List<IThemed> themed = new List<IThemed>();
        readonly Panel header = new Panel();
        readonly Label title = new Label();
        readonly Label subtitle = new Label();
        readonly FlowLayoutPanel toolbar = new FlowLayoutPanel();
        readonly Panel banner = new Panel();
        readonly Label bannerText = new Label();
        readonly FlowLayoutPanel chips = new FlowLayoutPanel();
        readonly TabStrip tabs = new TabStrip();
        readonly Panel content = new Panel();
        readonly Panel statusBar = new Panel();
        readonly Label statusLeft = new Label();
        readonly Label statusRight = new Label();

        FlatButton bRefresh, bSync, bSnapshot, bCompare, bWatch, bExport, bLogVice, bTheme, bSettings, bAbout, bAdmin;
        StatChip cEnroll, cMdm, cGpo, cConflict, cError, cOrphan, cUnmanaged, cFailed;

        readonly Table<ImeItem> ime = new Table<ImeItem>();
        readonly RichTextBox imeDetail = Detail();
        readonly ComboBox kindBox = Combo("All kinds");
        readonly FlatButton bFailedOnly = new FlatButton("Failed only", null);
        readonly FlatButton bImeLogs = new FlatButton("Open IME logs in LogVice", Glyphs.Log);
        readonly DeviceView deviceView = new DeviceView();
        bool imeFailedOnly;

        readonly Table<PolicySetting> settings = new Table<PolicySetting>();
        readonly Table<MdmError> events = new Table<MdmError>();
        readonly Table<Enrollment> enrollments = new Table<Enrollment>();
        readonly Table<AdmxFile> admx = new Table<AdmxFile>();
        readonly Table<Change> changes = new Table<Change>();
        readonly Table<RegistryEntry> registry = new Table<RegistryEntry>();
        readonly Table<RegistryEntry> denied = new Table<RegistryEntry>();
        readonly RichTextBox settingDetail = Detail();
        readonly RichTextBox eventDetail = Detail();
        readonly RichTextBox changeDetail = Detail();
        readonly Control[] views = new Control[9];

        readonly TextBox search = new TextBox();
        readonly ComboBox scopeBox = Combo("All scopes", "Device", "User");
        readonly ComboBox layerBox = Combo("All layers", Layers.Mdm, Layers.Registry);
        readonly ComboBox sourceBox = Combo("All sources", Sources.Intune, Sources.OtherMdm, Sources.GroupPolicy, Sources.MdmAdmx, Sources.Unmanaged, Sources.Unknown);
        readonly Label changesTitle = new Label();
        readonly FlatButton bWatchLog = new FlatButton("Show watch log", null);
        readonly FlatButton bExportChanges = new FlatButton("Export as HTML", Glyphs.Export);
        readonly System.Windows.Forms.Timer searchTimer = new System.Windows.Forms.Timer();
        string findingFilter;
        readonly List<Control> filterBar = new List<Control>();

        PolicyWatcher watcher;
        readonly List<Change> watchLog = new List<Change>();
        List<Change> comparison;
        string comparisonTitle;
        int watchCount;

        public MainForm(string openFile, bool demoMode)
        {
            demo = demoMode;
            Safe.Reporter = delegate (Exception ex) { Status("That did not work: " + ex.Message); };
            Safe.Status = delegate (string s) { Status(s); };
            Text = "PolicyVice";
            Icon = Program.AppIcon();
            Font = Fonts.Ui;
            KeyPreview = true;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(Dpi.S(1320), Dpi.S(840));
            MinimumSize = new Size(Dpi.S(900), Dpi.S(560));
            LoadBounds();
            BuildHeader();
            BuildViews();
            Controls.Add(content);
            Controls.Add(tabs);
            Controls.Add(chips);
            Controls.Add(banner);
            busyBar.Dock = DockStyle.Top;
            Controls.Add(busyBar);
            themed.Add(busyBar);
            Controls.Add(header);
            Controls.Add(statusBar);
            theme = Theme.Named(Prefs.Get("Theme", "System"));
            ApplyTheme();
            tabs.SelectedChanged += Safe.Wrap(delegate { ShowView(); });
            ShowView();
            Shown += Safe.Wrap(delegate
            {
                if (openFile != null) OpenSnapshot(openFile);
                else Reload(false);
            });
        }

        // ---------- building ----------

        void BuildHeader()
        {
            header.Dock = DockStyle.Top;
            header.Height = Dpi.S(64);
            header.Padding = new Padding(Dpi.S(20), Dpi.S(10), Dpi.S(12), Dpi.S(8));
            title.Text = "PolicyVice";
            title.Font = Fonts.Title;
            title.AutoSize = true;
            title.Location = new Point(Dpi.S(20), Dpi.S(8));
            subtitle.AutoSize = true;
            subtitle.Font = Fonts.Small;
            subtitle.Location = new Point(Dpi.S(22), Dpi.S(38));
            toolbar.Dock = DockStyle.Right;
            toolbar.AutoSize = true;
            toolbar.WrapContents = false;
            toolbar.FlowDirection = FlowDirection.LeftToRight;
            toolbar.Padding = new Padding(0, Dpi.S(6), 0, 0);

            bRefresh = Button("Refresh", Glyphs.Refresh, delegate { Reload(false); });
            bSync = Button("Sync", Glyphs2.Sync, delegate { Sync(); });
            bSnapshot = Button("Snapshot", Glyphs.Save, delegate { SnapshotMenu().Show(bSnapshot, new Point(0, bSnapshot.Height)); });
            bCompare = Button("Compare", Glyphs.Compare, delegate { CompareMenu().Show(bCompare, new Point(0, bCompare.Height)); });
            bWatch = Button("Watch", Glyphs.Watch, delegate { ToggleWatch(); });
            bExport = Button("Export", Glyphs.Export, delegate { ExportMenu().Show(bExport, new Point(0, bExport.Height)); });
            bLogVice = Button("LogVice", Glyphs.Log, delegate { LogViceMenu().Show(bLogVice, new Point(0, bLogVice.Height)); });
            bTheme = Button("", Glyphs.Theme, delegate { CycleTheme(); });
            bSettings = Button("", Glyphs2.Settings, delegate { OpenSettings(); });
            bAbout = Button("", Glyphs.Info, delegate { About(); });
            if (Fonts.Icons == null)
            {
                bTheme.Text = "Theme";
                bSettings.Text = "Settings";
                bAbout.Text = "About";
            }
            Tip(bRefresh, "Read the policies on this device again (F5)");
            Tip(bSync, "Start an MDM sync with Intune, like Sync under Access work or school");
            Tip(bSettings, "Settings (Ctrl+,)");
            Tip(bSnapshot, "Save or open a snapshot");
            Tip(bCompare, "Compare with a saved snapshot");
            Tip(bWatch, "Watch the policy registry keys and record every change");
            Tip(bExport, "Export an HTML report or CSV");
            Tip(bLogVice, "Open MDM and Intune logs in LogVice");
            Tip(bTheme, "Change the theme");
            Tip(bAbout, "About PolicyVice and the command line (F1)");
            foreach (FlatButton b in new FlatButton[] { bRefresh, bSync, bSnapshot, bCompare, bWatch, bExport, bLogVice, bTheme, bSettings, bAbout })
            {
                b.Margin = new Padding(Dpi.S(2), 0, 0, 0);
                toolbar.Controls.Add(b);
            }
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            header.Controls.Add(toolbar);

            banner.Dock = DockStyle.Top;
            banner.Height = Dpi.S(44);
            banner.Padding = new Padding(Dpi.S(20), Dpi.S(6), Dpi.S(20), Dpi.S(6));
            banner.Visible = false;
            bannerText.Dock = DockStyle.Fill;
            bannerText.TextAlign = ContentAlignment.MiddleLeft;
            bannerText.Text = "PolicyVice is not running as administrator. Some keys and Resultant Set of Policy need administrator rights, so owners may show as Unknown.";
            bAdmin = new FlatButton("Restart as administrator", Glyphs.Shield);
            bAdmin.Primary = true;
            bAdmin.Dock = DockStyle.Right;
            bAdmin.Click += Safe.Wrap(delegate { RestartElevated(); });
            themed.Add(bAdmin);
            banner.Controls.Add(bannerText);
            banner.Controls.Add(bAdmin);

            chips.Dock = DockStyle.Top;
            chips.Height = Dpi.S(78);
            chips.Padding = new Padding(Dpi.S(18), Dpi.S(8), Dpi.S(18), Dpi.S(8));
            chips.WrapContents = false;
            cEnroll = Chip("Enrollments", 0, delegate { tabs.Selected = TabEnroll; });
            cMdm = Chip("MDM settings", 0, delegate { QuickFilter(null, Layers.Mdm, null); });
            cGpo = Chip("Group Policy values", 0, delegate { QuickFilter(null, null, Sources.GroupPolicy); });
            cConflict = Chip("Conflicts", 2, delegate { QuickFilter(FindingKinds.Conflict, null, null); });
            cError = Chip("Settings with errors", 2, delegate { QuickFilter(FindingKinds.Error, null, null); });
            cOrphan = Chip("Orphans", 1, delegate { QuickFilter(FindingKinds.Orphan, null, null); });
            cUnmanaged = Chip("Unmanaged values", 1, delegate { QuickFilter(FindingKinds.Unmanaged, null, null); });
            cFailed = Chip("Failed apps and scripts", 2, delegate { FilterIme(!(imeFailedOnly && tabs.Selected == TabIntune)); tabs.Selected = TabIntune; });
            Tip(cFailed, "Win32 apps, scripts and remediations that failed on this device");
            Tip(cOrphan, "MDM values that no provider sent any more");
            Tip(cUnmanaged, "Policy registry values that no GPO and no MDM setting claims, often tattooed");
            Tip(cConflict, "Settings that both MDM and Group Policy configure");

            tabs.Dock = DockStyle.Top;
            tabs.SetTabs("Settings", "Intune apps and scripts", "MDM events", "Device", "Enrollments", "ADMX", "Changes", "Policy registry", "Access denied");
            themed.Add(tabs);

            content.Dock = DockStyle.Fill;
            content.Padding = new Padding(Dpi.S(16), Dpi.S(12), Dpi.S(16), Dpi.S(8));

            statusBar.Dock = DockStyle.Bottom;
            statusBar.Height = Dpi.S(28);
            statusBar.Padding = new Padding(Dpi.S(18), 0, Dpi.S(18), 0);
            statusLeft.Dock = DockStyle.Fill;
            statusLeft.TextAlign = ContentAlignment.MiddleLeft;
            statusLeft.AutoEllipsis = true;
            statusRight.Dock = DockStyle.Right;
            statusRight.AutoSize = true;
            statusRight.TextAlign = ContentAlignment.MiddleRight;
            statusRight.Padding = new Padding(0, Dpi.S(6), 0, 0);
            statusBar.Controls.Add(statusLeft);
            statusBar.Controls.Add(statusRight);
        }

        void BuildViews()
        {
            // Settings
            Panel filters = new Panel();
            filters.Dock = DockStyle.Top;
            filters.Height = Dpi.S(44);
            FlowLayoutPanel fl = new FlowLayoutPanel();
            fl.Dock = DockStyle.Fill;
            fl.WrapContents = false;
            search.Width = Dpi.S(300);
            search.BorderStyle = BorderStyle.FixedSingle;
            search.Font = Fonts.Ui;
            search.Margin = new Padding(0, Dpi.S(6), Dpi.S(10), 0);
            Cue(search, "Search settings, values, areas and GPOs (Ctrl+F)");
            searchTimer.Interval = 200;
            searchTimer.Tick += Safe.Wrap(delegate { searchTimer.Stop(); BindSettings(); });
            search.TextChanged += delegate { searchTimer.Stop(); searchTimer.Start(); };
            fl.Controls.Add(search);
            foreach (ComboBox c in new ComboBox[] { scopeBox, layerBox, sourceBox })
            {
                c.Margin = new Padding(0, Dpi.S(6), Dpi.S(8), 0);
                c.SelectedIndexChanged += Safe.Wrap(delegate { BindSettings(); });
                fl.Controls.Add(c);
            }
            FlatButton clear = new FlatButton("Clear filters", null);
            clear.Compact = true;
            clear.AutoWidth();
            clear.Margin = new Padding(0, Dpi.S(2), 0, 0);
            clear.Click += Safe.Wrap(delegate { QuickFilter(null, null, null); search.Text = ""; });
            themed.Add(clear);
            fl.Controls.Add(clear);
            filters.Controls.Add(fl);
            filterBar.Add(filters);
            filterBar.Add(fl);

            settings.Col("Setting", 250, delegate (PolicySetting p) { return p.DisplayName; }).Fill = true;
            Column<PolicySetting> val = settings.Col("Value", 150, delegate (PolicySetting p) { return p.Value; });
            val.Fill = true;
            settings.Grid.Columns[1].DefaultCellStyle.Font = Fonts.Mono;
            settings.Col("Source", 96, delegate (PolicySetting p) { return p.Source; });
            settings.Col("Findings", 104, delegate (PolicySetting p) { return Kinds(p); });
            settings.Col("Area", 150, delegate (PolicySetting p) { return p.Area; }).Fill = true;
            settings.Col("Scope", 62, delegate (PolicySetting p) { return p.Scope; });
            settings.Col("Layer", 66, delegate (PolicySetting p) { return p.Layer; });
            settings.ForeColor = delegate (PolicySetting p)
            {
                if (p.Has(FindingKinds.Conflict) || p.Has(FindingKinds.Error)) return theme.ErrFg;
                if (p.Has(FindingKinds.Orphan) || p.Has(FindingKinds.Unmanaged)) return theme.WarnFg;
                return Color.Empty;
            };
            settings.SelectionChanged += delegate { ShowSetting(settings.Current); };
            settings.MenuExtras = SettingExtras;
            settings.EmptyText = "No settings match the filters.";
            views[TabSettings] = Split(settings.Grid, settingDetail, filters);

            // Intune apps and scripts
            Panel imeBar = new Panel();
            imeBar.Dock = DockStyle.Top;
            imeBar.Height = Dpi.S(44);
            imeBar.Padding = new Padding(0, Dpi.S(2), 0, Dpi.S(10));
            FlowLayoutPanel ifl = new FlowLayoutPanel();
            ifl.Dock = DockStyle.Fill;
            ifl.WrapContents = false;
            kindBox.Width = Dpi.S(170);
            kindBox.Margin = new Padding(0, Dpi.S(6), Dpi.S(8), 0);
            kindBox.SelectedIndexChanged += Safe.Wrap(delegate { BindIntune(); });
            ifl.Controls.Add(kindBox);
            bFailedOnly.Compact = true;
            bFailedOnly.AutoWidth();
            bFailedOnly.Margin = new Padding(0, Dpi.S(2), 0, 0);
            bFailedOnly.Click += Safe.Wrap(delegate { FilterIme(!imeFailedOnly); });
            ifl.Controls.Add(bFailedOnly);
            bImeLogs.Dock = DockStyle.Right;
            bImeLogs.Click += Safe.Wrap(delegate { OpenInLogVice(LogViceLink.ImeLogs()); });
            Tip(bImeLogs, "Open IntuneManagementExtension.log, and AppWorkload.log when it exists, in LogVice");
            Tip(bFailedOnly, "Show only the apps and scripts that failed");
            themed.Add(bFailedOnly);
            themed.Add(bImeLogs);
            imeBar.Controls.Add(ifl);
            imeBar.Controls.Add(bImeLogs);
            filterBar.Add(imeBar);
            filterBar.Add(ifl);
            ime.Col("Kind", 110, delegate (ImeItem i) { return i.Kind; });
            ime.Col("Name", 260, delegate (ImeItem i) { return ImeName(i); }).Fill = true;
            ime.Col("Status", 140, delegate (ImeItem i) { return i.Status; });
            ime.Col("Error", 110, delegate (ImeItem i) { return i.ErrorCode; });
            ime.Col("Time", 150, delegate (ImeItem i) { return ImeTime(i); });
            ime.Col("User", 180, delegate (ImeItem i) { return i.User; }).Fill = true;
            ime.ForeColor = delegate (ImeItem i) { return i.Failed ? theme.ErrFg : Color.Empty; };
            ime.SelectionChanged += delegate { ShowIme(ime.Current); };
            ime.MenuExtras = delegate (ContextMenuStrip m, ImeItem i)
            {
                if (!string.IsNullOrEmpty(i.Id)) Menus.Add(m, "Copy ID", delegate { Menus.Copy(i.Id); });
                if (!string.IsNullOrEmpty(i.RegistryPath)) Menus.Add(m, "Copy registry path", delegate { Menus.Copy(i.RegistryPath); });
                if (!string.IsNullOrEmpty(i.Detail)) Menus.Add(m, "Copy details", delegate { Menus.Copy(imeDetail.Text.Trim()); });
                Menus.Separator(m);
                Menus.Add(m, "Open IME logs in LogVice", delegate { OpenInLogVice(LogViceLink.ImeLogs()); });
            };
            views[TabIntune] = Split(ime.Grid, imeDetail, imeBar);

            // Device
            views[TabDevice] = deviceView;

            // MDM events
            events.Col("Time", 150, delegate (MdmError e) { return e.Time.ToString("yyyy-MM-dd HH:mm:ss", Inv); });
            events.Col("Event", 60, delegate (MdmError e) { return e.EventId.ToString(Inv); });
            events.Col("Level", 80, delegate (MdmError e) { return e.Level; });
            events.Col("Setting", 200, delegate (MdmError e) { return e.Area == null ? "" : e.Area + "/" + e.Name; }).Fill = true;
            events.Col("Result", 220, delegate (MdmError e) { return e.Result ?? Txt.Short(e.Message, 200); }).Fill = true;
            events.ForeColor = delegate (MdmError e) { return e.Level == "Error" ? theme.ErrFg : e.Level == "Warning" ? theme.WarnFg : Color.Empty; };
            events.SelectionChanged += delegate { ShowEvent(events.Current); };
            events.EmptyText = "No MDM errors or warnings in the DeviceManagement Admin event log for the days read.";
            events.MenuExtras = delegate (ContextMenuStrip m, MdmError e)
            {
                if (!string.IsNullOrEmpty(e.CspUri)) Menus.Add(m, "Copy CSP URI", delegate { Menus.Copy(e.CspUri); });
                Menus.Add(m, "Copy message", delegate { Menus.Copy(e.Message); });
                Menus.Separator(m);
                Menus.Add(m, "Open MDM events in LogVice", delegate { OpenInLogVice(LogViceLink.MdmAdmin); });
            };
            views[TabEvents] = Split(events.Grid, eventDetail, null);

            enrollments.Col("Provider", 120, delegate (Enrollment e) { return e.ProviderName; });
            enrollments.Col("User", 220, delegate (Enrollment e) { return e.Upn; }).Fill = true;
            enrollments.Col("Type", 60, delegate (Enrollment e) { return e.EnrollmentType.ToString(Inv); });
            enrollments.Col("State", 60, delegate (Enrollment e) { return e.EnrollmentState.ToString(Inv); });
            enrollments.Col("Enrollment ID", 300, delegate (Enrollment e) { return e.Id; }).Fill = true;
            enrollments.Col("Discovery URL", 300, delegate (Enrollment e) { return e.DiscoveryUrl; }).Fill = true;
            enrollments.EmptyText = "This device has no MDM enrollment.";
            enrollments.MenuExtras = delegate (ContextMenuStrip m, Enrollment e) { Menus.Add(m, "Copy enrollment ID", delegate { Menus.Copy(e.Id); }); };
            views[TabEnroll] = Card(enrollments.Grid);

            admx.Col("App", 180, delegate (AdmxFile a) { return a.App; }).Fill = true;
            admx.Col("Setting type", 100, delegate (AdmxFile a) { return a.SettingType; });
            admx.Col("File ID", 200, delegate (AdmxFile a) { return a.Id; }).Fill = true;
            admx.Col("Policies read", 100, delegate (AdmxFile a) { return a.Policies.ToString(Inv); });
            admx.Col("Provider", 300, delegate (AdmxFile a) { return a.ProviderId; }).Fill = true;
            views[TabAdmx] = Card(admx.Grid);

            Panel ch = new Panel();
            ch.Dock = DockStyle.Top;
            ch.Height = Dpi.S(44);
            changesTitle.Dock = DockStyle.Fill;
            changesTitle.TextAlign = ContentAlignment.MiddleLeft;
            changesTitle.Font = Fonts.UiSemibold;
            bWatchLog.Dock = DockStyle.Right;
            bWatchLog.Click += Safe.Wrap(delegate { comparison = null; BindChanges(); });
            bExportChanges.Dock = DockStyle.Right;
            bExportChanges.Click += Safe.Wrap(delegate { ExportChanges(); });
            themed.Add(bWatchLog);
            themed.Add(bExportChanges);
            ch.Controls.Add(changesTitle);
            ch.Controls.Add(bWatchLog);
            ch.Controls.Add(bExportChanges);
            filterBar.Add(ch);
            changes.Col("Time", 150, delegate (Change c) { return c.Time.ToString("yyyy-MM-dd HH:mm:ss", Inv); });
            changes.Col("Change", 80, delegate (Change c) { return c.Kind; });
            changes.Col("Setting", 220, delegate (Change c) { return c.Setting; }).Fill = true;
            changes.Col("Area", 160, delegate (Change c) { return c.Area; }).Fill = true;
            changes.Col("Before", 140, delegate (Change c) { return c.OldValue; }).Fill = true;
            changes.Col("After", 140, delegate (Change c) { return c.NewValue; }).Fill = true;
            changes.Col("Source", 110, delegate (Change c) { return c.NewSource ?? c.OldSource; });
            changes.Col("Layer", 76, delegate (Change c) { return c.Layer; });
            changes.ForeColor = delegate (Change c) { return c.Kind == Differ.Removed ? theme.ErrFg : c.Kind == Differ.Added ? theme.OkFg : Color.Empty; };
            changes.SelectionChanged += delegate { ShowChange(changes.Current); };
            changes.MenuExtras = delegate (ContextMenuStrip m, Change c)
            {
                if (!string.IsNullOrEmpty(c.RegistryPath)) Menus.Add(m, "Copy registry path", delegate { Menus.Copy(c.RegistryPath); });
                Menus.Add(m, "Copy details", delegate { Menus.Copy(changeDetail.Text.Trim()); });
                Menus.Separator(m);
                Menus.Add(m, "Open MDM events in LogVice", delegate { OpenInLogVice(LogViceLink.MdmAdmin); });
            };
            views[TabChanges] = Split(changes.Grid, changeDetail, ch);

            Column<RegistryEntry> rp = registry.Col("Key", 420, delegate (RegistryEntry r) { return r.Path; });
            rp.Fill = true;
            registry.Col("Value name", 200, delegate (RegistryEntry r) { return string.IsNullOrEmpty(r.Name) ? "(Default)" : r.Name; });
            registry.Col("Type", 100, delegate (RegistryEntry r) { return r.Kind; });
            registry.Col("Data", 260, delegate (RegistryEntry r) { return r.Data; }).Fill = true;
            registry.EmptyText = "No values under SOFTWARE\\Policies.";
            views[TabRegistry] = Card(registry.Grid);

            denied.Col("Key that could not be read", 600, delegate (RegistryEntry r) { return r.Path; }).Fill = true;
            denied.EmptyText = "Every key could be read.";
            views[TabDenied] = Card(denied.Grid);

            foreach (Control v in views)
            {
                v.Visible = false;
                content.Controls.Add(v);
            }
            themed.Add(settings);
            themed.Add(ime);
            themed.Add(deviceView);
            themed.Add(events);
            themed.Add(enrollments);
            themed.Add(admx);
            themed.Add(changes);
            themed.Add(registry);
            themed.Add(denied);
        }

        Control Split(Control grid, RichTextBox detail, Control top)
        {
            Panel host = new Panel();
            host.Dock = DockStyle.Fill;
            SplitContainer sp = new SplitContainer();
            sp.Dock = DockStyle.Fill;
            sp.Orientation = Orientation.Vertical;
            sp.SplitterWidth = Dpi.S(10);
            sp.FixedPanel = FixedPanel.Panel2;
            sp.Panel1.Controls.Add(Card(grid));
            Panel dc = Card(detail);
            sp.Panel2.Controls.Add(dc);
            host.Controls.Add(sp);
            if (top != null) host.Controls.Add(top);
            sp.Tag = false;
            host.Resize += delegate
            {
                try
                {
                    int want = Math.Min(Dpi.S(440), Math.Max(Dpi.S(260), host.Width / 3));
                    if (sp.Width > want + Dpi.S(200) && Math.Abs(sp.Width - sp.SplitterDistance - sp.SplitterWidth - want) > Dpi.S(4) && !sp.Tag.Equals(true))
                        sp.SplitterDistance = sp.Width - want - sp.SplitterWidth;
                }
                catch (Exception) { }
            };
            sp.SplitterMoved += delegate { if (sp.Focused) sp.Tag = true; };
            return host;
        }

        Panel Card(Control inner)
        {
            Panel p = new Panel();
            p.Dock = DockStyle.Fill;
            p.Padding = new Padding(1);
            p.Tag = "card";
            inner.Dock = DockStyle.Fill;
            p.Controls.Add(inner);
            return p;
        }

        static RichTextBox Detail()
        {
            RichTextBox r = new RichTextBox();
            r.ReadOnly = true;
            r.BorderStyle = BorderStyle.None;
            r.DetectUrls = false;
            r.WordWrap = true;
            r.ScrollBars = RichTextBoxScrollBars.Vertical;
            return r;
        }

        static ComboBox Combo(params string[] items)
        {
            ComboBox c = new ComboBox();
            c.DropDownStyle = ComboBoxStyle.DropDownList;
            c.FlatStyle = FlatStyle.Flat;
            c.Items.AddRange(items);
            c.SelectedIndex = 0;
            c.Width = Dpi.S(130);
            return c;
        }

        FlatButton Button(string text, string glyph, EventHandler click)
        {
            FlatButton b = new FlatButton(text, glyph);
            b.Click += Safe.Wrap(click);
            themed.Add(b);
            return b;
        }

        StatChip Chip(string label, int tone, EventHandler click)
        {
            StatChip c = new StatChip(label, tone);
            c.Margin = new Padding(0, 0, Dpi.S(10), 0);
            c.Click += Safe.Wrap(click);
            themed.Add(c);
            chips.Controls.Add(c);
            return c;
        }

        readonly ToolTip tips = new ToolTip();

        void Tip(Control c, string text)
        {
            tips.SetToolTip(c, text);
        }

        static void Cue(TextBox box, string text)
        {
            try { SendMessage(box.Handle, 0x1501, (IntPtr)1, text); } catch (Exception) { }
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        // ---------- theme ----------

        void CycleTheme()
        {
            string[] order = { "System", "Light", "Dark", "Vice" };
            string cur = Prefs.Get("Theme", "System");
            int i = Array.IndexOf(order, cur);
            string next = order[(i + 1) % order.Length];
            Prefs.Set("Theme", next);
            theme = Theme.Named(next);
            ApplyTheme();
            Status("Theme: " + (next == "System" ? "follow Windows (" + theme.Name + ")" : next));
        }

        void ApplyTheme()
        {
            Theme t = theme;
            BackColor = t.Bg;
            ForeColor = t.Text;
            foreach (Control c in new Control[] { header, toolbar, chips, content, statusBar })
            {
                c.BackColor = t.Bg;
                c.ForeColor = t.Text;
            }
            title.ForeColor = t.Text;
            subtitle.ForeColor = t.Text3;
            banner.BackColor = t.WarnBg;
            bannerText.ForeColor = t.Text;
            statusLeft.ForeColor = t.Text3;
            statusRight.ForeColor = t.Text3;
            changesTitle.ForeColor = t.Text;
            foreach (Control c in filterBar) c.BackColor = t.Bg;
            foreach (Control v in views) Recolor(v, t);
            search.BackColor = t.Field;
            search.ForeColor = t.Text;
            foreach (ComboBox c in new ComboBox[] { scopeBox, layerBox, sourceBox, kindBox })
            {
                c.BackColor = t.Field;
                c.ForeColor = t.Text;
            }
            foreach (RichTextBox r in new RichTextBox[] { settingDetail, eventDetail, changeDetail, imeDetail })
            {
                r.BackColor = t.Card;
                r.ForeColor = t.Text;
            }
            foreach (IThemed x in themed) x.ApplyTheme(t);
            try
            {
                int dark = t.IsDark ? 1 : 0;
                DwmSetWindowAttribute(Handle, 20, ref dark, 4);
            }
            catch (Exception) { }
            ShowSetting(settings.Current);
            ShowEvent(events.Current);
            ShowChange(changes.Current);
            ShowIme(ime.Current);
            Invalidate(true);
        }

        void Recolor(Control c, Theme t)
        {
            if (c is SplitContainer)
            {
                c.BackColor = t.Bg;
                ((SplitContainer)c).Panel1.BackColor = t.Bg;
                ((SplitContainer)c).Panel2.BackColor = t.Bg;
            }
            else if (c is Panel && "card".Equals(c.Tag)) c.BackColor = t.Divider;
            else if (c is Panel || c is FlowLayoutPanel) c.BackColor = t.Bg;
            foreach (Control k in c.Controls) Recolor(k, t);
        }

        // ---------- loading ----------

        void Reload(bool fromWatch)
        {
            if (busy)
            {
                // Keep the request: read again as soon as the current read is done.
                pending = true;
                pendingWatch |= fromWatch;
                Status("Still reading. Another read follows when this one is done…");
                return;
            }
            busy = true;
            bRefresh.Enabled = false;
            busyBar.Running = true;
            Status(demo ? "Loading demo data…" : "Reading policies, ADMX definitions, MDM events, apps and scripts…");
            Cursor = Cursors.AppStarting;
            int days = Prefs.GetInt("EventDays", 7, 1, 90);
            int variant = fromWatch ? watchCount % 2 : 0;
            ThreadPool.QueueUserWorkItem(delegate
            {
                Snapshot s = null;
                Exception err = null;
                try { s = demo ? Demo.Build(variant) : Program.CollectLive(days); }
                catch (Exception ex) { err = ex; }
                try
                {
                    BeginInvoke((MethodInvoker)delegate { Loaded(s, err, fromWatch); });
                }
                catch (Exception) { }
            });
        }

        void Loaded(Snapshot s, Exception err, bool fromWatch)
        {
            busy = false;
            bRefresh.Enabled = true;
            busyBar.Running = false;
            Cursor = Cursors.Default;
            try
            {
                if (err != null) Status("Reading failed: " + err.Message);
                else
                {
                    Snapshot before = snap != null && snapFile == null ? snap : null;
                    snapFile = null;
                    Bind(s);
                    if (fromWatch && before != null) RecordWatch(before, s);
                }
            }
            catch (Exception ex) { Safe.Report(ex); }
            if (pending)
            {
                bool w = pendingWatch;
                pending = pendingWatch = false;
                Reload(w);
            }
        }

        void OpenSnapshot(string path)
        {
            try
            {
                Snapshot s = Snapshot.Load(path);
                if (watcher != null) ToggleWatch();
                if (busy) pending = pendingWatch = false;
                snapFile = path;
                Bind(s);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "The snapshot could not be opened: " + ex.Message, "PolicyVice", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                if (snap == null) Reload(false);
            }
        }

        void Bind(Snapshot s)
        {
            snap = s;
            string when = s.TakenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", Inv);
            subtitle.Text = (snapFile != null ? "Snapshot · " : demo ? "Demo data · " : "") + s.Computer + " · " + s.UserName + " · " + s.OsVersion + " · " + when;
            Text = "PolicyVice - " + s.Computer + (snapFile != null ? " (snapshot)" : demo ? " (demo)" : "");
            banner.Visible = snapFile == null && !demo && !s.Elevated;
            bWatch.Enabled = snapFile == null;
            bSync.Enabled = snapFile == null && !syncing;
            if (s.Device == null) s.Device = new DeviceInfo();
            if (s.Device.Items == null) s.Device.Items = new List<InfoItem>();
            if (s.Intune == null) s.Intune = new List<ImeItem>();
            s.Intune.RemoveAll(delegate (ImeItem i) { return i == null; });
            int failed = 0;
            foreach (ImeItem i in s.Intune) if (i.Failed) failed++;
            cFailed.Count = failed;
            deviceView.SetItems(s.Device.Items, s.Computer + (snapFile != null ? " (snapshot " + Path.GetFileName(snapFile) + ")" : ""));
            BindKinds(s);
            BindIntune();
            cEnroll.Count = s.Enrollments.Count;
            cMdm.Count = s.CountLayer(Layers.Mdm);
            cGpo.Count = s.CountSource(Sources.GroupPolicy);
            cConflict.Count = s.Count(FindingKinds.Conflict);
            cError.Count = s.Count(FindingKinds.Error);
            cOrphan.Count = s.Count(FindingKinds.Orphan);
            cUnmanaged.Count = s.Count(FindingKinds.Unmanaged);
            foreach (Control c in chips.Controls) c.Invalidate();
            BindSettings();
            events.SetRows(new List<MdmError>(s.Errors));
            enrollments.SetRows(new List<Enrollment>(s.Enrollments));
            admx.SetRows(new List<AdmxFile>(s.AdmxFiles));
            registry.SetRows(new List<RegistryEntry>(s.PolicyRegistry));
            List<RegistryEntry> den = new List<RegistryEntry>();
            foreach (string p in s.AccessDenied)
            {
                RegistryEntry r = new RegistryEntry();
                r.Path = p;
                den.Add(r);
            }
            denied.SetRows(den);
            tabs.SetText(TabEvents, "MDM events (" + s.Errors.Count + ")");
            tabs.SetText(TabDenied, "Access denied (" + s.AccessDenied.Count + ")");
            BindChanges();
            string rsop = s.RsopAvailable ? "Resultant Set of Policy read" : (s.RsopNote ?? "Resultant Set of Policy not read");
            statusRight.Text = "MDMWinsOverGP " + (s.MdmWinsOverGp ? "on" : "off") + "  ·  " + rsop + "  ·  PolicyVice " + Program.Version;
            if (s.Enrollments.Count == 0 && s.CountLayer(Layers.Mdm) == 0) Status("This device has no MDM enrollment and no MDM policy.");
            else Status(s.Settings.Count + " settings read" + (snapFile != null ? " from " + Path.GetFileName(snapFile) : "") + ".");
        }

        void QuickFilter(string finding, string layer, string source)
        {
            findingFilter = finding;
            layerBox.SelectedIndex = layer == null ? 0 : layerBox.Items.IndexOf(layer);
            sourceBox.SelectedIndex = source == null ? 0 : sourceBox.Items.IndexOf(source);
            cConflict.Selected = finding == FindingKinds.Conflict;
            cError.Selected = finding == FindingKinds.Error;
            cOrphan.Selected = finding == FindingKinds.Orphan;
            cUnmanaged.Selected = finding == FindingKinds.Unmanaged;
            cMdm.Selected = finding == null && layer == Layers.Mdm && source == null;
            cGpo.Selected = finding == null && source == Sources.GroupPolicy && layer == null;
            foreach (Control c in chips.Controls) c.Invalidate();
            tabs.Selected = TabSettings;
            BindSettings();
        }

        void BindSettings()
        {
            if (snap == null) return;
            string q = search.Text.Trim();
            string scope = scopeBox.SelectedIndex > 0 ? (string)scopeBox.SelectedItem : null;
            string layer = layerBox.SelectedIndex > 0 ? (string)layerBox.SelectedItem : null;
            string source = sourceBox.SelectedIndex > 0 ? (string)sourceBox.SelectedItem : null;
            List<PolicySetting> list = new List<PolicySetting>();
            foreach (PolicySetting p in snap.Settings)
            {
                if (scope != null && p.Scope != scope) continue;
                if (layer != null && p.Layer != layer) continue;
                if (source != null && p.Source != source) continue;
                if (findingFilter != null && !p.Has(findingFilter)) continue;
                if (q.Length > 0 && !Matches(p, q)) continue;
                list.Add(p);
            }
            settings.SetRows(list);
            string filter = findingFilter != null ? findingFilter.ToLowerInvariant() + " " : "";
            tabs.SetText(TabSettings, list.Count == snap.Settings.Count ? "Settings (" + list.Count + ")" : "Settings (" + list.Count + " of " + snap.Settings.Count + ")");
            if (findingFilter != null) Status(list.Count + " " + filter + "settings shown.");
        }

        void BindKinds(Snapshot s)
        {
            string keep = kindBox.SelectedIndex > 0 ? (string)kindBox.SelectedItem : null;
            List<string> kinds = new List<string>();
            foreach (ImeItem i in s.Intune) if (!string.IsNullOrEmpty(i.Kind) && !kinds.Contains(i.Kind)) kinds.Add(i.Kind);
            kinds.Sort(StringComparer.OrdinalIgnoreCase);
            kindBox.BeginUpdate();
            kindBox.Items.Clear();
            kindBox.Items.Add("All kinds");
            foreach (string k in kinds) kindBox.Items.Add(k);
            int idx = keep == null ? 0 : kindBox.Items.IndexOf(keep);
            kindBox.SelectedIndex = idx < 0 ? 0 : idx;
            kindBox.EndUpdate();
        }

        void FilterIme(bool failedOnly)
        {
            imeFailedOnly = failedOnly;
            BindIntune();
            if (failedOnly) Status(cFailed.Count + " failed apps and scripts shown.");
        }

        void BindIntune()
        {
            bFailedOnly.Checked = imeFailedOnly;
            bFailedOnly.Invalidate();
            cFailed.Selected = imeFailedOnly;
            cFailed.Invalidate();
            if (snap == null) return;
            string kind = kindBox.SelectedIndex > 0 ? (string)kindBox.SelectedItem : null;
            List<ImeItem> list = new List<ImeItem>();
            foreach (ImeItem i in snap.Intune)
            {
                if (kind != null && i.Kind != kind) continue;
                if (imeFailedOnly && !i.Failed) continue;
                list.Add(i);
            }
            list.Sort(delegate (ImeItem a, ImeItem b)
            {
                if (a.Failed != b.Failed) return a.Failed ? -1 : 1;
                int c = string.Compare(a.Kind, b.Kind, StringComparison.OrdinalIgnoreCase);
                return c != 0 ? c : string.Compare(ImeName(a), ImeName(b), StringComparison.OrdinalIgnoreCase);
            });
            ime.EmptyText = snap.Intune.Count == 0
                ? "The Intune Management Extension has no apps or scripts on this device."
                : "No apps or scripts match the filter.";
            ime.SetRows(list);
            int total = snap.Intune.Count;
            tabs.SetText(TabIntune, list.Count == total ? "Intune apps and scripts (" + total + ")" : "Intune apps and scripts (" + list.Count + " of " + total + ")");
            ShowIme(ime.Current);
        }

        static string ImeName(ImeItem i)
        {
            return string.IsNullOrEmpty(i.Name) ? i.Id : i.Name;
        }

        static string ImeTime(ImeItem i)
        {
            if (!i.Time.HasValue) return "";
            DateTime t = i.Time.Value;
            if (t.Kind == DateTimeKind.Utc) t = t.ToLocalTime();
            return t.ToString("yyyy-MM-dd HH:mm:ss", Inv);
        }

        void ShowIme(ImeItem i)
        {
            RichTextBox r = imeDetail;
            Begin(r);
            if (i == null)
            {
                r.SelectionColor = theme.Text3;
                r.AppendText(snap != null && snap.Intune.Count == 0
                    ? "\nThe Intune Management Extension has no apps or scripts on this device. Win32 apps, platform scripts and remediations appear here once Intune assigns them and the extension has run."
                    : "\nSelect an app or script to see the details.");
                End(r);
                return;
            }
            r.AppendText("\n");
            Heading(r, ImeName(i) ?? "");
            Line(r, i.Failed ? "Failed" : "OK", i.Failed ? theme.ErrFg : theme.OkFg, (i.Kind ?? "") + (string.IsNullOrEmpty(i.Status) ? "" : " · " + i.Status));
            Field(r, "Error code", i.ErrorCode, true);
            Field(r, "Time", ImeTime(i), false);
            Field(r, "User", i.User, false);
            Field(r, "ID", i.Id, true);
            Field(r, "Registry", i.RegistryPath, true);
            if (!string.IsNullOrEmpty(i.Detail))
            {
                Section(r, "Details");
                r.SelectionFont = Fonts.Ui;
                r.SelectionColor = theme.Text2;
                r.AppendText(i.Detail.Trim() + "\n");
            }
            End(r);
        }

        static bool Matches(PolicySetting p, string q)
        {
            foreach (string f in new string[] { p.FriendlyName, p.Name, p.Area, p.Value, p.Source, p.SourceDetail, p.RegistryPath, p.CspUri })
                if (f != null && f.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        static string Kinds(PolicySetting p)
        {
            if (p.Findings.Count == 0) return "";
            List<string> k = new List<string>();
            foreach (Finding f in p.Findings) if (!k.Contains(f.Kind)) k.Add(f.Kind);
            return string.Join(", ", k.ToArray());
        }

        void ShowView()
        {
            for (int i = 0; i < views.Length; i++) views[i].Visible = i == tabs.Selected;
        }

        void Status(string text)
        {
            statusLeft.Text = text;
        }

        // ---------- detail panes ----------

        void Heading(RichTextBox r, string text)
        {
            r.SelectionFont = Fonts.Title;
            r.SelectionColor = theme.Text;
            r.AppendText(text + "\n");
        }

        void Section(RichTextBox r, string text)
        {
            r.SelectionFont = Fonts.UiSemibold;
            r.SelectionColor = theme.Text;
            r.AppendText("\n" + text + "\n");
        }

        void Field(RichTextBox r, string label, string value, bool mono)
        {
            if (string.IsNullOrEmpty(value)) return;
            r.SelectionFont = Fonts.Small;
            r.SelectionColor = theme.Text3;
            r.AppendText(label + "\n");
            r.SelectionFont = mono ? Fonts.Mono : Fonts.Ui;
            r.SelectionColor = theme.Text;
            r.AppendText(value + "\n");
        }

        void Line(RichTextBox r, string tag, Color tagColor, string text)
        {
            r.SelectionFont = Fonts.UiSemibold;
            r.SelectionColor = tagColor;
            r.AppendText(tag + "  ");
            r.SelectionFont = Fonts.Ui;
            r.SelectionColor = theme.Text;
            r.AppendText(text + "\n");
        }

        void Begin(RichTextBox r)
        {
            r.SuspendLayout();
            r.Clear();
            r.SelectionIndent = Dpi.S(12);
            r.SelectionRightIndent = Dpi.S(8);
        }

        void End(RichTextBox r)
        {
            r.SelectionStart = 0;
            r.ScrollToCaret();
            r.ResumeLayout();
        }

        void ShowSetting(PolicySetting p)
        {
            RichTextBox r = settingDetail;
            Begin(r);
            if (p == null)
            {
                r.SelectionColor = theme.Text3;
                r.AppendText("\nSelect a setting to see where it comes from.");
                End(r);
                return;
            }
            r.AppendText("\n");
            Heading(r, p.DisplayName);
            if (p.Findings.Count > 0)
            {
                Section(r, "Findings");
                foreach (Finding f in p.Findings)
                    Line(r, f.Kind, f.Kind == FindingKinds.Conflict || f.Kind == FindingKinds.Error ? theme.ErrFg : theme.WarnFg, f.Message);
            }
            Section(r, "Setting");
            Field(r, "Value", p.Value, true);
            Field(r, "Type", p.ValueKind, false);
            Field(r, "Source", p.Source + (string.IsNullOrEmpty(p.SourceDetail) ? "" : " · " + p.SourceDetail), false);
            Field(r, "Scope", p.Scope + (p.UserSid != null ? " · " + p.UserSid : ""), false);
            Field(r, "Name", p.Area + (p.Layer == Layers.Mdm ? "/" : "\\") + p.Name, true);
            Field(r, "CSP URI", p.CspUri, true);
            Field(r, "Registry", p.RegistryPath, true);
            Field(r, "Winning provider", p.WinningProvider, true);
            if (p.Contributions.Count > 0)
            {
                Section(r, "Who sets it");
                foreach (Contribution c in p.Contributions)
                    Line(r, c.Wins ? "Wins" : "Also", c.Wins ? theme.OkFg : theme.Text3, c.Source + " · " + c.Detail + (string.IsNullOrEmpty(c.Value) ? "" : " = " + Txt.Short(c.Value, 200)));
            }
            if (!string.IsNullOrEmpty(p.Description))
            {
                Section(r, "Description");
                r.SelectionFont = Fonts.Ui;
                r.SelectionColor = theme.Text2;
                r.AppendText(p.Description.Trim() + "\n");
            }
            End(r);
        }

        void ShowEvent(MdmError e)
        {
            RichTextBox r = eventDetail;
            Begin(r);
            if (e == null)
            {
                r.SelectionColor = theme.Text3;
                r.AppendText("\nSelect an event to see the full message.");
                End(r);
                return;
            }
            r.AppendText("\n");
            Heading(r, "Event " + e.EventId + " · " + e.Level);
            Field(r, "Time", e.Time.ToString("yyyy-MM-dd HH:mm:ss", Inv), false);
            Field(r, "CSP URI", e.CspUri, true);
            Field(r, "Result", e.Result, false);
            if (snap != null && e.Area != null)
            {
                foreach (PolicySetting p in snap.Settings)
                    if (p.Layer == Layers.Mdm && p.Scope == e.Scope && string.Equals(p.Area, e.Area, StringComparison.OrdinalIgnoreCase) && string.Equals(p.Name, e.Name, StringComparison.OrdinalIgnoreCase))
                        Field(r, "Current value", p.Value + "  (" + p.Source + ")", true);
            }
            Section(r, "Message");
            r.SelectionFont = Fonts.Ui;
            r.SelectionColor = theme.Text2;
            r.AppendText(e.Message + "\n");
            End(r);
        }

        void ShowChange(Change c)
        {
            RichTextBox r = changeDetail;
            Begin(r);
            if (c == null)
            {
                r.SelectionColor = theme.Text3;
                r.AppendText(comparison == null
                    ? "\nTurn on Watch to record every change to the policy registry keys, with the MDM events around it. Or use Compare to compare with a saved snapshot."
                    : "\nSelect a change to see the details.");
                End(r);
                return;
            }
            r.AppendText("\n");
            Heading(r, c.Setting);
            Line(r, c.Kind, c.Kind == Differ.Removed ? theme.ErrFg : c.Kind == Differ.Added ? theme.OkFg : theme.WarnFg, c.Time.ToString("yyyy-MM-dd HH:mm:ss", Inv));
            Field(r, "Before", c.OldValue, true);
            Field(r, "After", c.NewValue, true);
            Field(r, "Source", c.OldSource == c.NewSource || c.OldSource == null ? c.NewSource : c.NewSource == null ? c.OldSource : c.OldSource + " → " + c.NewSource, false);
            Field(r, "Name", c.Area + (c.Layer == Layers.Mdm ? "/" : "\\") + c.Name, true);
            Field(r, "Registry", c.RegistryPath, true);
            if (c.Events.Count > 0)
            {
                Section(r, "MDM events within 2 minutes");
                foreach (MdmError e in c.Events)
                    Line(r, e.EventId + " " + e.Level, e.Level == "Error" ? theme.ErrFg : theme.WarnFg, e.Time.ToString("HH:mm:ss", Inv) + " " + (e.CspUri ?? "") + " " + (e.Result ?? ""));
            }
            End(r);
        }

        // ---------- watch and compare ----------

        void ToggleWatch()
        {
            if (watcher != null)
            {
                watcher.Dispose();
                watcher = null;
                bWatch.Checked = false;
                bWatch.Text = "Watch";
                Status("Watch stopped. " + watchLog.Count + " changes recorded.");
                return;
            }
            if (demo)
            {
                bWatch.Checked = true;
                bWatch.Text = "Watching";
                Status("Watching (demo): a simulated change arrives in a few seconds.");
                System.Windows.Forms.Timer t = new System.Windows.Forms.Timer();
                t.Interval = 2500;
                t.Tick += delegate { t.Stop(); t.Dispose(); if (bWatch.Checked) { watchCount++; Reload(true); } };
                t.Start();
                watcher = new PolicyWatcher();
                return;
            }
            watcher = new PolicyWatcher();
            watcher.Changed += delegate
            {
                try { BeginInvoke((MethodInvoker)delegate { watchCount++; Safe.Run(delegate { Reload(true); }); }); } catch (Exception) { }
            };
            watcher.Start();
            bWatch.Checked = true;
            bWatch.Text = "Watching";
            Status("Watching PolicyManager and the Policies keys. Changes appear on the Changes tab.");
        }

        void RecordWatch(Snapshot before, Snapshot after)
        {
            List<Change> found = Differ.Compare(before, after);
            DateTime now = DateTime.Now;
            foreach (Change c in found) c.Time = now;
            List<MdmError> recent = new List<MdmError>(after.Errors);
            if (demo) foreach (MdmError e in recent) e.Time = now.AddSeconds(-20);
            Differ.AttachEvents(found, recent, TimeSpan.FromMinutes(2));
            watchLog.InsertRange(0, found);
            if (found.Count > 0)
            {
                Status(found.Count + " change" + (found.Count == 1 ? "" : "s") + " at " + now.ToString("HH:mm:ss", Inv) + ". See the Changes tab.");
                FlashWindow();
            }
            else Status("Policy keys were written at " + now.ToString("HH:mm:ss", Inv) + ", but no setting changed.");
            BindChanges();
        }

        void BindChanges()
        {
            if (comparison != null)
            {
                changesTitle.Text = comparisonTitle + " · " + comparison.Count + " differences";
                changes.SetRows(new List<Change>(comparison));
                bWatchLog.Visible = true;
                tabs.SetText(TabChanges, "Changes (" + comparison.Count + ")");
            }
            else
            {
                changesTitle.Text = watcher != null ? "Watch log · " + watchLog.Count + " changes so far" : watchLog.Count > 0 ? "Watch log · " + watchLog.Count + " changes" : "Watch log";
                changes.SetRows(new List<Change>(watchLog));
                bWatchLog.Visible = false;
                tabs.SetText(TabChanges, watchLog.Count > 0 ? "Changes (" + watchLog.Count + ")" : "Changes");
            }
            ShowChange(changes.Current);
        }

        void CompareWith(Snapshot a, string titleA, Snapshot b, string titleB)
        {
            comparison = Differ.Compare(a, b);
            comparisonTitle = titleA + " → " + titleB;
            BindChanges();
            tabs.Selected = TabChanges;
            Status(comparison.Count + " differences.");
        }

        void ExportChanges()
        {
            List<Change> list = comparison ?? watchLog;
            string path = SaveDialog("HTML report|*.html", "PolicyVice changes " + DateTime.Now.ToString("yyyy-MM-dd HHmm", Inv) + ".html");
            if (path == null) return;
            try
            {
                File.WriteAllText(path, Report.DiffHtml(comparison != null ? comparisonTitle : "Watch log", snap != null ? Cli.Title(snap) : "", list, Program.Version));
                OpenFile(path);
            }
            catch (Exception ex) { Fail(ex); }
        }

        void FlashWindow()
        {
            if (ContainsFocus) return;
            try
            {
                FLASHWINFO f = new FLASHWINFO();
                f.cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO));
                f.hwnd = Handle;
                f.dwFlags = 3 | 12;
                f.uCount = 3;
                FlashWindowEx(ref f);
            }
            catch (Exception) { }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        [DllImport("user32.dll")]
        static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        // ---------- menus ----------

        ContextMenuStrip NewMenu()
        {
            ContextMenuStrip m = new ContextMenuStrip();
            m.Renderer = new ToolStripProfessionalRenderer(new MenuColors(theme));
            m.BackColor = theme.Card;
            m.ForeColor = theme.Text;
            m.Font = Fonts.Ui;
            m.ShowImageMargin = false;
            return m;
        }

        ToolStripMenuItem Item(ContextMenuStrip m, string text, EventHandler click)
        {
            ToolStripMenuItem i = new ToolStripMenuItem(text, null, Safe.Wrap(click));
            i.ForeColor = theme.Text;
            i.Padding = new Padding(Dpi.S(4), Dpi.S(3), Dpi.S(4), Dpi.S(3));
            m.Items.Add(i);
            return i;
        }

        ContextMenuStrip SnapshotMenu()
        {
            ContextMenuStrip m = NewMenu();
            Item(m, "Save snapshot…  (Ctrl+S)", delegate { SaveSnapshot(); }).Enabled = snap != null;
            Item(m, "Open snapshot…", delegate
            {
                string p = OpenDialog();
                if (p != null) OpenSnapshot(p);
            });
            if (snapFile != null || demo) Item(m, "Back to this device", delegate { demo = false; Reload(false); });
            return m;
        }

        ContextMenuStrip CompareMenu()
        {
            ContextMenuStrip m = NewMenu();
            Item(m, "Compare with a saved snapshot…", delegate
            {
                if (snap == null) return;
                string p = OpenDialog();
                if (p == null) return;
                try
                {
                    Snapshot old = Snapshot.Load(p);
                    CompareWith(old, Cli.Title(old), snap, snapFile != null ? Cli.Title(snap) : "now");
                }
                catch (Exception ex) { Fail(ex); }
            }).Enabled = snap != null;
            Item(m, "Compare two snapshots…", delegate
            {
                string a = OpenDialog();
                if (a == null) return;
                string b = OpenDialog();
                if (b == null) return;
                try
                {
                    Snapshot sa = Snapshot.Load(a), sb = Snapshot.Load(b);
                    CompareWith(sa, Cli.Title(sa), sb, Cli.Title(sb));
                }
                catch (Exception ex) { Fail(ex); }
            });
            return m;
        }

        ContextMenuStrip ExportMenu()
        {
            ContextMenuStrip m = NewMenu();
            Item(m, "HTML report…  (Ctrl+E)", delegate { ExportHtml(); }).Enabled = snap != null;
            Item(m, "CSV of all settings…", delegate
            {
                if (snap == null) return;
                string p = SaveDialog("CSV file|*.csv", FileName("csv"));
                if (p == null) return;
                try { Report.Csv(snap, p); Status("Saved " + Path.GetFileName(p)); }
                catch (Exception ex) { Fail(ex); }
            }).Enabled = snap != null;
            return m;
        }

        ContextMenuStrip LogViceMenu()
        {
            ContextMenuStrip m = NewMenu();
            Item(m, "MDM events (Admin)", delegate { OpenInLogVice(LogViceLink.MdmAdmin); });
            Item(m, "MDM events (Operational)", delegate { OpenInLogVice(LogViceLink.MdmOperational); });
            Item(m, "Intune Management Extension logs", delegate { OpenInLogVice(LogViceLink.ImeLogs()); });
            Item(m, "Group Policy events", delegate { OpenInLogVice(LogViceLink.GroupPolicy); });
            Item(m, "Entra ID (AAD) events", delegate { OpenInLogVice(LogViceLink.Aad); });
            m.Items.Add(new ToolStripSeparator());
            Item(m, "Locate LogVice…", delegate { LocateLogVice(); });
            return m;
        }

        void SettingExtras(ContextMenuStrip m, PolicySetting p)
        {
            Menus.Add(m, "Copy value", delegate { Menus.Copy(p.Value); });
            Menus.Add(m, "Copy setting name", delegate { Menus.Copy(p.DisplayName); });
            if (!string.IsNullOrEmpty(p.CspUri)) Menus.Add(m, "Copy CSP URI", delegate { Menus.Copy(p.CspUri); });
            Menus.Add(m, "Copy registry path", delegate { Menus.Copy(p.RegistryPath); });
            Menus.Add(m, "Copy details", delegate { Menus.Copy(settingDetail.Text.Trim()); });
            Menus.Separator(m);
            Menus.Add(m, "Open MDM events in LogVice", delegate { OpenInLogVice(LogViceLink.MdmAdmin); });
        }

        // ---------- actions ----------

        void OpenInLogVice(params string[] targets)
        {
            if (targets == null || targets.Length == 0) return;
            string exe = LogViceLink.Find();
            if (exe == null)
            {
                DialogResult r = MessageBox.Show(this, "LogVice was not found on this computer. Do you want to locate LogVice.exe?", "PolicyVice", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r != DialogResult.Yes) return;
                exe = LocateLogVice();
                if (exe == null) return;
            }
            try
            {
                LogViceLink.Open(exe, targets);
                List<string> names = new List<string>();
                foreach (string t in targets) names.Add(t.StartsWith("evt:") ? t.Substring(4) : Path.GetFileName(t));
                Status("Opened in LogVice: " + string.Join(", ", names.ToArray()));
            }
            catch (Exception ex) { Fail(ex); }
        }

        void RestartElevated()
        {
            if (Program.RestartElevated()) Close();
            else Status("PolicyVice was not restarted as administrator.");
        }

        // ---------- sync ----------

        void Sync()
        {
            if (syncing) { Status("A sync is already starting."); return; }
            if (snap == null || snapFile != null) { Status("Sync works on this device. Open Snapshot > Back to this device first."); return; }
            List<string> ids = new List<string>();
            foreach (Enrollment e in snap.Enrollments) if (e.IsIntune && !string.IsNullOrEmpty(e.Id)) ids.Add(e.Id);
            if (ids.Count == 0)
            {
                MessageBox.Show(this, "This device has no Intune enrollment, so there is nothing to sync.", "Sync", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (!demo && !Program.IsAdmin)
            {
                DialogResult r = MessageBox.Show(this,
                    "Starting an MDM sync needs administrator rights, because Windows runs the sync tasks as SYSTEM.\n\n" +
                    "Restart PolicyVice as administrator now? You can also select Sync under Settings > Accounts > Access work or school.",
                    "Sync", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if (r == DialogResult.Yes) RestartElevated();
                return;
            }
            syncing = true;
            bSync.Enabled = false;
            bSync.Text = "Syncing";
            busyBar.Running = true;
            Status("Starting the MDM sync for " + ids.Count + (ids.Count == 1 ? " Intune enrollment…" : " Intune enrollments…"));
            bool sim = demo;
            ThreadPool.QueueUserWorkItem(delegate
            {
                SyncResult res = null;
                Exception err = null;
                try { res = sim ? MdmSync.Simulate(ids) : MdmSync.Start(ids); }
                catch (Exception ex) { err = ex; }
                try { BeginInvoke((MethodInvoker)delegate { SyncDone(res, err); }); }
                catch (Exception) { }
            });
        }

        void SyncDone(SyncResult res, Exception err)
        {
            syncing = false;
            bSync.Text = "Sync";
            bSync.Enabled = snapFile == null;
            busyBar.Running = busy;
            if (err != null || res == null || res.Started == 0)
            {
                string why = err != null ? err.Message : res == null ? "" : string.Join("\n", res.Lines.ToArray());
                Status("The MDM sync did not start.");
                MessageBox.Show(this, "The MDM sync did not start.\n\n" + why + "\n\nYou can also select Sync under Settings > Accounts > Access work or school.", "Sync", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string msg = "MDM sync started at " + DateTime.Now.ToString("HH:mm:ss", Inv) + ". New policy arrives over the next minutes.";
            if (watcher == null && snapFile == null && Prefs.GetBool("WatchAfterSync", true))
            {
                ToggleWatch();
                msg += " Watch is on and records every change.";
            }
            else if (watcher != null) msg += " Watch records every change.";
            else msg += " Press F5 to read the device again.";
            Status(msg);
        }

        // ---------- settings and about ----------

        void OpenSettings()
        {
            using (SettingsDialog d = new SettingsDialog(theme))
            {
                d.ThemeChanged += delegate
                {
                    theme = Theme.Named(Prefs.Get("Theme", "System"));
                    ApplyTheme();
                };
                d.ShowDialog(this);
                if (d.RestartRequested) { RestartElevated(); return; }
                if (d.DaysChanged && snapFile == null) Reload(false);
            }
        }

        string LocateLogVice()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Filter = "LogVice|LogVice.exe|Programs|*.exe";
                d.Title = "Locate LogVice";
                if (d.ShowDialog(this) != DialogResult.OK) return null;
                Prefs.Set("LogVicePath", d.FileName);
                return d.FileName;
            }
        }

        void SaveSnapshot()
        {
            if (snap == null) return;
            string p = SaveDialog("PolicyVice snapshot|*.json", FileName("json"));
            if (p == null) return;
            try
            {
                snap.Save(p);
                Prefs.Set("SnapshotFolder", Path.GetDirectoryName(p));
                Status("Saved snapshot " + Path.GetFileName(p));
            }
            catch (Exception ex) { Fail(ex); }
        }

        void ExportHtml()
        {
            if (snap == null) return;
            string p = SaveDialog("HTML report|*.html", FileName("html"));
            if (p == null) return;
            try
            {
                File.WriteAllText(p, Report.Html(snap), new UTF8Encoding(false));
                OpenFile(p);
                Status("Saved report " + Path.GetFileName(p));
            }
            catch (Exception ex) { Fail(ex); }
        }

        string FileName(string ext)
        {
            return "PolicyVice " + snap.Computer + " " + snap.TakenUtc.ToLocalTime().ToString("yyyy-MM-dd HHmm", Inv) + "." + ext;
        }

        string SaveDialog(string filter, string name)
        {
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = filter;
                d.FileName = name;
                string dir = Prefs.Get("SnapshotFolder", null);
                if (dir != null && Directory.Exists(dir)) d.InitialDirectory = dir;
                return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
            }
        }

        string OpenDialog()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Filter = "PolicyVice snapshot|*.json|All files|*.*";
                string dir = Prefs.Get("SnapshotFolder", null);
                if (dir != null && Directory.Exists(dir)) d.InitialDirectory = dir;
                return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
            }
        }

        static void OpenFile(string path)
        {
            try { System.Diagnostics.Process.Start(path); } catch (Exception) { }
        }

        void Fail(Exception ex)
        {
            MessageBox.Show(this, ex.Message, "PolicyVice", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        void About()
        {
            using (AboutDialog d = new AboutDialog(theme)) d.ShowDialog(this);
        }

        // ---------- window ----------

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            try
            {
                switch (keyData)
                {
                    case Keys.F5: Reload(false); return true;
                    case Keys.F1: About(); return true;
                    case Keys.Control | Keys.Oemcomma: OpenSettings(); return true;
                    case Keys.Control | Keys.F: tabs.Selected = TabSettings; search.Focus(); search.SelectAll(); return true;
                    case Keys.Control | Keys.S: SaveSnapshot(); return true;
                    case Keys.Control | Keys.E: ExportHtml(); return true;
                    case Keys.Escape:
                        if (search.Focused && search.Text.Length > 0) { search.Text = ""; return true; }
                        break;
                }
            }
            catch (Exception ex)
            {
                Safe.Report(ex);
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        void LoadBounds()
        {
            string b = Prefs.Get("Bounds", null);
            if (b == null) return;
            string[] p = b.Split(',');
            int x, y, w, h;
            if (p.Length != 4 || !int.TryParse(p[0], out x) || !int.TryParse(p[1], out y) || !int.TryParse(p[2], out w) || !int.TryParse(p[3], out h)) return;
            Rectangle r = new Rectangle(x, y, w, h);
            foreach (Screen s in Screen.AllScreens)
            {
                if (!s.WorkingArea.IntersectsWith(r)) continue;
                StartPosition = FormStartPosition.Manual;
                Bounds = r;
                if (Prefs.Get("Maximized", "0") == "1") WindowState = FormWindowState.Maximized;
                return;
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            Rectangle r = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
            Prefs.Set("Bounds", r.X + "," + r.Y + "," + r.Width + "," + r.Height);
            Prefs.Set("Maximized", WindowState == FormWindowState.Maximized ? "1" : "0");
            try { if (watcher != null) watcher.Dispose(); } catch (Exception) { }
            base.OnFormClosing(e);
        }
    }

    sealed class MenuColors : ProfessionalColorTable
    {
        readonly Theme t;

        public MenuColors(Theme theme)
        {
            t = theme;
            UseSystemColors = false;
        }

        public override Color ToolStripDropDownBackground { get { return t.Card; } }
        public override Color MenuBorder { get { return t.Divider; } }
        public override Color MenuItemBorder { get { return t.Hover; } }
        public override Color MenuItemSelected { get { return t.Hover; } }
        public override Color MenuItemSelectedGradientBegin { get { return t.Hover; } }
        public override Color MenuItemSelectedGradientEnd { get { return t.Hover; } }
        public override Color ImageMarginGradientBegin { get { return t.Card; } }
        public override Color ImageMarginGradientMiddle { get { return t.Card; } }
        public override Color ImageMarginGradientEnd { get { return t.Card; } }
        public override Color SeparatorDark { get { return t.Divider; } }
        public override Color SeparatorLight { get { return t.Divider; } }
    }
}
