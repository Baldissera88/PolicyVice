namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;

    public static class Program
    {
        public const string Developer = "Daniel L. Baldissera";
        public const string BuildDate = "8 November 2026";

        [DllImport("kernel32.dll")]
        static extern bool AttachConsole(int pid);

        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        public static string Version
        {
            get
            {
                object[] a = typeof(Program).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false);
                return a.Length > 0 ? ((System.Reflection.AssemblyInformationalVersionAttribute)a[0]).InformationalVersion : typeof(Program).Assembly.GetName().Version.ToString();
            }
        }

        public static string Location
        {
            get
            {
                try
                {
                    string p = typeof(Program).Assembly.Location;
                    return string.IsNullOrEmpty(p) ? Application.ExecutablePath : p;
                }
                catch (Exception) { return Application.ExecutablePath; }
            }
        }

        public static bool IsAdmin
        {
            get
            {
                try
                {
                    return new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
                catch (Exception) { return false; }
            }
        }

        public static string CurrentSid
        {
            get
            {
                try { return System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; }
                catch (Exception) { return null; }
            }
        }

        static Icon icon;

        public static Icon AppIcon()
        {
            if (icon != null) return icon;
            try
            {
                using (Stream s = typeof(Program).Assembly.GetManifestResourceStream("PolicyVice.ico"))
                {
                    if (s != null) icon = new Icon(s);
                }
            }
            catch (Exception) { }
            return icon;
        }

        public static string OsVersion()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey hklm = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64))
                using (Microsoft.Win32.RegistryKey k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (k != null)
                    {
                        string name = Convert.ToString(k.GetValue("ProductName"));
                        string disp = Convert.ToString(k.GetValue("DisplayVersion"));
                        string build = Convert.ToString(k.GetValue("CurrentBuild"));
                        object ubr = k.GetValue("UBR");
                        int b;
                        if (int.TryParse(build, out b) && b >= 22000) name = name.Replace("Windows 10", "Windows 11");
                        return (name + " " + disp).Trim() + " (" + build + (ubr != null ? "." + ubr : "") + ")";
                    }
                }
            }
            catch (Exception) { }
            return Environment.OSVersion.VersionString;
        }

        public static CollectOptions Options(int days)
        {
            CollectOptions o = new CollectOptions();
            o.EventDays = days;
            o.CurrentUserSid = CurrentSid;
            o.Computer = Environment.MachineName;
            o.UserName = Environment.UserDomainName + "\\" + Environment.UserName;
            o.OsVersion = OsVersion();
            o.Elevated = IsAdmin;
            o.Version = Version;
            return o;
        }

        static AdmxCatalog catalog;

        public static AdmxCatalog Catalog()
        {
            if (catalog != null) return catalog;
            AdmxCatalog c = new AdmxCatalog();
            c.LoadFolder(AdmxCatalog.DefaultFolder);
            c.LoadIngested(AdmxCatalog.IngestionFolder);
            catalog = c;
            return c;
        }

        public static Snapshot CollectLive(int days)
        {
            return Collector.Collect(new LiveRegistry(), new LiveRsop(), new LiveEvents(), Catalog(), Options(days));
        }

        public static bool RestartElevated()
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                System.Diagnostics.Process.Start(psi);
                return true;
            }
            catch (Exception) { return false; }
        }

        [STAThread]
        public static int Main(string[] args)
        {
            if (args != null && args.Length > 0 && (args[0].StartsWith("/") || args[0].StartsWith("-")) && !IsDemo(args[0]))
            {
                try { AttachConsole(-1); } catch (Exception) { }
                Console.WriteLine();
                int code = Cli.Run(args);
                return code;
            }
            AppDomain.CurrentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e)
            {
                Exception ex = e.ExceptionObject as Exception;
                MessageBox.Show(ex != null ? ex.ToString() : "Unknown error", "PolicyVice", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            try { SetProcessDPIAware(); } catch (Exception) { }
            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }
            catch (InvalidOperationException) { }
            try
            {
                using (Graphics g = Graphics.FromHwnd(IntPtr.Zero)) Dpi.Scale = Math.Max(1f, g.DpiX / 96f);
            }
            catch (Exception) { }
            Fonts.Init();
            Application.ThreadException += delegate (object sender, System.Threading.ThreadExceptionEventArgs e)
            {
                MessageBox.Show(e.Exception.Message, "PolicyVice", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            string open = null;
            bool demo = false;
            foreach (string a in args ?? new string[0])
            {
                if (IsDemo(a)) demo = true;
                else if (a.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) open = a;
            }
            using (MainForm f = new MainForm(open, demo))
            {
                Application.Run(f);
            }
            return 0;
        }

        static bool IsDemo(string a)
        {
            return string.Equals(a, "--demo", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "/demo", StringComparison.OrdinalIgnoreCase);
        }
    }

    // Command line use, for scripts and Intune remediations.
    public static class Cli
    {
        public static void Usage()
        {
            Console.WriteLine("PolicyVice " + Program.Version + " - policy inspector for Intune, MDM and Group Policy");
            Console.WriteLine();
            Console.WriteLine("  PolicyVice.exe                         Open the window");
            Console.WriteLine("  PolicyVice.exe <snapshot.json>         Open a saved snapshot");
            Console.WriteLine("  PolicyVice.exe /snapshot <file.json>   Save a snapshot of this device");
            Console.WriteLine("  PolicyVice.exe /report <file.html>     Save an HTML report of this device");
            Console.WriteLine("  PolicyVice.exe /csv <file.csv>         Save all settings as CSV");
            Console.WriteLine("  PolicyVice.exe /diff <a.json> <b.json> [/out <file.html>]");
            Console.WriteLine("                                         Compare two snapshots");
            Console.WriteLine("  /days <n>                              Days of MDM events to read (default 7)");
            Console.WriteLine();
            Console.WriteLine("Exit codes: 0 done, 1 error, 2 findings were found (for /snapshot, /report and /csv)");
        }

        public static int Run(string[] args)
        {
            string snapshot = null, report = null, csv = null, out_ = null;
            List<string> diff = new List<string>();
            int days = 7;
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i].TrimStart('/', '-').ToLowerInvariant();
                    switch (a)
                    {
                        case "snapshot": snapshot = Next(args, ref i); break;
                        case "report": report = Next(args, ref i); break;
                        case "csv": csv = Next(args, ref i); break;
                        case "out": out_ = Next(args, ref i); break;
                        case "days": days = int.Parse(Next(args, ref i)); break;
                        case "diff": diff.Add(Next(args, ref i)); diff.Add(Next(args, ref i)); break;
                        case "?":
                        case "h":
                        case "help": Usage(); return 0;
                        default: throw new ArgumentException("Unknown option: " + args[i]);
                    }
                }
                if (diff.Count == 2)
                {
                    Snapshot a = Snapshot.Load(diff[0]), b = Snapshot.Load(diff[1]);
                    List<Change> changes = Differ.Compare(a, b);
                    foreach (Change c in changes)
                        Console.WriteLine(c.Kind.PadRight(8) + " " + c.Layer.PadRight(8) + " " + c.Area + "\\" + c.Name + "  " + (c.OldValue ?? "") + " -> " + (c.NewValue ?? ""));
                    Console.WriteLine(changes.Count + " differences");
                    if (out_ != null) File.WriteAllText(out_, Report.DiffHtml(Title(a), Title(b), changes, Program.Version));
                    return 0;
                }
                if (snapshot == null && report == null && csv == null)
                {
                    Usage();
                    return 1;
                }
                Snapshot s = Program.CollectLive(days);
                if (snapshot != null) s.Save(snapshot);
                if (report != null) File.WriteAllText(report, Report.Html(s));
                if (csv != null) Report.Csv(s, csv);
                int conflicts = s.Count(FindingKinds.Conflict), errors = s.Count(FindingKinds.Error), orphans = s.Count(FindingKinds.Orphan), unmanaged = s.Count(FindingKinds.Unmanaged);
                Console.WriteLine(s.Computer + ": " + s.CountLayer(Layers.Mdm) + " MDM settings, " + s.CountSource(Sources.GroupPolicy) + " Group Policy values, " +
                    conflicts + " conflicts, " + errors + " with errors, " + orphans + " orphans, " + unmanaged + " unmanaged");
                if (!s.Elevated) Console.WriteLine("Not run as administrator: some keys and Resultant Set of Policy may be missing.");
                return conflicts + errors + orphans + unmanaged > 0 ? 2 : 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("PolicyVice: " + ex.Message);
                return 1;
            }
        }

        public static string Title(Snapshot s)
        {
            return s.Computer + " " + s.TakenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture);
        }

        static string Next(string[] args, ref int i)
        {
            if (i + 1 >= args.Length) throw new ArgumentException("Missing value after " + args[i]);
            return args[++i];
        }
    }
}
