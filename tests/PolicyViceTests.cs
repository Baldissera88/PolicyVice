namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    public sealed class FakeRegistry : IRegSource
    {
        readonly Dictionary<string, Dictionary<string, RegValue>> keys = new Dictionary<string, Dictionary<string, RegValue>>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> denied = new List<string>();

        public List<string> Denied
        {
            get { return denied; }
        }

        public void Set(string path, string name, string kind, string data)
        {
            Ensure(path)[name] = new RegValue(kind, data);
        }

        Dictionary<string, RegValue> Ensure(string path)
        {
            Dictionary<string, RegValue> v;
            if (!keys.TryGetValue(path, out v))
            {
                v = new Dictionary<string, RegValue>(StringComparer.OrdinalIgnoreCase);
                keys[path] = v;
                int i = path.LastIndexOf('\\');
                if (i > 0) Ensure(path.Substring(0, i));
            }
            return v;
        }

        public string[] SubKeys(string path)
        {
            List<string> l = new List<string>();
            string prefix = path + "\\";
            foreach (string k in keys.Keys)
            {
                if (!k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                string rest = k.Substring(prefix.Length);
                if (rest.IndexOf('\\') < 0) l.Add(rest);
            }
            l.Sort(StringComparer.OrdinalIgnoreCase);
            return l.ToArray();
        }

        public string[] ValueNames(string path)
        {
            Dictionary<string, RegValue> v;
            if (!keys.TryGetValue(path, out v)) return new string[0];
            return new List<string>(v.Keys).ToArray();
        }

        public RegValue Get(string path, string name)
        {
            Dictionary<string, RegValue> v;
            RegValue r;
            return keys.TryGetValue(path, out v) && v.TryGetValue(name, out r) ? r : null;
        }
    }

    public sealed class FakeRsop : IRsopSource
    {
        public List<RsopValue> Values = new List<RsopValue>();
        public string Note;

        public List<RsopValue> ComputerValues(out string note)
        {
            note = Note;
            return Values;
        }

        public void Add(string key, string name, string data, string gpo, int prec)
        {
            RsopValue r = new RsopValue();
            r.Key = key;
            r.ValueName = name;
            r.Data = data;
            r.Kind = "REG_DWORD";
            r.GpoName = gpo;
            r.GpoId = "{" + gpo + "}";
            r.Precedence = prec;
            Values.Add(r);
        }
    }

    public sealed class FakeEvents : IEventSource
    {
        public List<EventItem> Items = new List<EventItem>();

        public List<EventItem> Read(string channel, DateTime since, bool errorsOnly)
        {
            return Items;
        }
    }

    public static class Program
    {
        static int failed, passed;

        const string IntuneId = "3A1B2C3D-0000-4000-8000-000000000001";
        const string Pm = @"HKLM\SOFTWARE\Microsoft\PolicyManager";
        const string UserSid = "S-1-12-1-1111-2222-3333-4444";

        static void Check(bool ok, string what)
        {
            if (ok) passed++;
            else
            {
                failed++;
                Console.WriteLine("FAIL: " + what);
            }
        }

        public static FakeRegistry SampleRegistry()
        {
            FakeRegistry r = new FakeRegistry();
            string e = @"HKLM\SOFTWARE\Microsoft\Enrollments\" + IntuneId;
            r.Set(e, "ProviderID", "REG_SZ", "MS DM Server");
            r.Set(e, "UPN", "REG_SZ", "anna@contoso.com");
            r.Set(e, "EnrollmentType", "REG_DWORD", "6");
            r.Set(e, "EnrollmentState", "REG_DWORD", "1");
            r.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\Context", "x", "REG_SZ", "y");

            string dev = Pm + @"\current\device";
            r.Set(dev + @"\Update", "AllowAutoUpdate", "REG_DWORD", "1");
            r.Set(dev + @"\Update", "AllowAutoUpdate_ProviderSet", "REG_DWORD", "1");
            r.Set(dev + @"\Update", "AllowAutoUpdate_WinningProvider", "REG_SZ", IntuneId);
            r.Set(dev + @"\Defender", "AllowRealtimeMonitoring", "REG_DWORD", "1");
            r.Set(dev + @"\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS", "REG_SZ", "<enabled/>");
            r.Set(dev + @"\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS_WinningProvider", "REG_SZ", IntuneId);
            r.Set(dev + @"\OneDriveNGSCv2~Policy~OneDriveNGSC", "KFMSilentOptIn", "REG_SZ", "<enabled/><data id=\"KFMSilentOptInBox\" value=\"tenant\"/>");
            r.Set(dev + @"\ControlPolicyConflict", "MDMWinsOverGP", "REG_DWORD", "1");
            r.Set(Pm + @"\current\" + UserSid + @"\Start", "HideRecentlyAddedApps", "REG_DWORD", "1");

            string prov = Pm + @"\providers\" + IntuneId + @"\default";
            r.Set(prov + @"\Device\Update", "AllowAutoUpdate", "REG_DWORD", "1");
            r.Set(prov + @"\Device\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS", "REG_SZ", "<enabled/>");
            r.Set(prov + @"\Device\OneDriveNGSCv2~Policy~OneDriveNGSC", "KFMSilentOptIn", "REG_SZ", "<enabled/>");
            r.Set(prov + @"\" + UserSid + @"\Start", "HideRecentlyAddedApps", "REG_DWORD", "1");

            r.Set(Pm + @"\AdmxInstalled\" + IntuneId + @"\OneDriveNGSCv2\Policy\OneDriveAdmx", "x", "REG_SZ", "1");

            string pol = @"HKLM\SOFTWARE\Policies\Microsoft";
            r.Set(pol + @"\Windows NT\Terminal Services", "fDenyTSConnections", "REG_DWORD", "1");
            r.Set(pol + @"\Windows\WindowsUpdate\AU", "NoAutoUpdate", "REG_DWORD", "0");
            r.Set(pol + @"\OneDrive", "KFMSilentOptIn", "REG_SZ", "tenant");
            r.Set(pol + @"\Leftover", "Foo", "REG_DWORD", "1");
            r.Set(@"HKCU\SOFTWARE\Policies\Microsoft\Office", "Bar", "REG_SZ", "baz");
            return r;
        }

        public static AdmxCatalog SampleCatalog()
        {
            AdmxCatalog c = new AdmxCatalog();
            c.Load("TerminalServer",
                "<?xml version=\"1.0\"?><policyDefinitions><policies><policy name=\"TS_DISABLE_CONNECTIONS\" class=\"Machine\" displayName=\"$(string.TS_DISABLE_CONNECTIONS)\" explainText=\"$(string.TS_DISABLE_CONNECTIONS_EXPLAIN)\" key=\"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" valueName=\"fDenyTSConnections\"/></policies></policyDefinitions>",
                "<?xml version=\"1.0\"?><policyDefinitionResources><resources><stringTable><string id=\"TS_DISABLE_CONNECTIONS\">Allow users to connect remotely by using Remote Desktop Services</string><string id=\"TS_DISABLE_CONNECTIONS_EXPLAIN\">Controls remote access.</string></stringTable></resources></policyDefinitionResources>",
                false);
            c.Load("OneDrive_ingested",
                "<policyDefinitions><policies><policy name=\"KFMSilentOptIn\" class=\"Machine\" displayName=\"Silently move Windows known folders to OneDrive\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"><elements><text id=\"KFMSilentOptInBox\" valueName=\"KFMSilentOptIn\"/></elements></policy></policies></policyDefinitions>",
                null, true);
            return c;
        }

        public static FakeRsop SampleRsop()
        {
            FakeRsop r = new FakeRsop();
            r.Add(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections", "1", "Baseline - RDP", 1);
            r.Add(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections", "0", "Old RDP", 2);
            r.Add(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "0", "WSUS", 1);
            return r;
        }

        public static FakeEvents SampleEvents()
        {
            FakeEvents ev = new FakeEvents();
            EventItem i = new EventItem();
            i.Time = new DateTime(2026, 11, 8, 10, 0, 5);
            i.Id = 404;
            i.Level = "Error";
            i.Message = "MDM ConfigurationManager: Command failure status. Configuration Source ID: (" + IntuneId + "), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), Command Type: (CmdType_Add), CSP URI: (./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring), Result: (The parameter is incorrect.).";
            ev.Items.Add(i);
            EventItem w = new EventItem();
            w.Time = new DateTime(2026, 11, 8, 10, 0, 7);
            w.Id = 813;
            w.Level = "Warning";
            w.Message = "Something without a URI, code 0x80070057.";
            ev.Items.Add(w);
            return ev;
        }

        static PolicySetting Find(Snapshot s, string layer, string area, string name)
        {
            foreach (PolicySetting p in s.Settings)
                if (p.Layer == layer && string.Equals(p.Area, area, StringComparison.OrdinalIgnoreCase) && p.Name == name) return p;
            return null;
        }

        public static Snapshot Sample()
        {
            CollectOptions o = new CollectOptions();
            o.Computer = "PC-0042";
            o.UserName = "CONTOSO\\anna";
            o.OsVersion = "Windows 11 25H2 (26200.1)";
            o.Elevated = true;
            o.Version = "0.1.0";
            o.CurrentUserSid = UserSid;
            o.NowUtc = new DateTime(2026, 11, 8, 9, 30, 0, DateTimeKind.Utc);
            return Collector.Collect(SampleRegistry(), SampleRsop(), SampleEvents(), SampleCatalog(), o);
        }

        public static int Main(string[] args)
        {
            Snapshot s = Sample();

            Check(s.Enrollments.Count == 1 && s.Enrollments[0].IsIntune && s.Enrollments[0].Upn == "anna@contoso.com", "one Intune enrollment");
            Check(s.MdmWinsOverGp, "MDMWinsOverGP read");
            Check(s.AdmxFiles.Count == 1 && s.AdmxFiles[0].App == "OneDriveNGSCv2", "ADMX installed listed");

            PolicySetting upd = Find(s, Layers.Mdm, "Update", "AllowAutoUpdate");
            Check(upd != null && upd.Source == Sources.Intune && upd.SourceDetail == "anna@contoso.com", "Update from Intune");
            Check(upd != null && upd.FriendlyName == "Allow Auto Update", "camel case name");
            Check(upd != null && upd.CspUri == "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate", "CSP URI");
            Check(upd != null && upd.Contributions.Count == 1 && upd.Contributions[0].Wins, "winning contribution");
            Check(Find(s, Layers.Mdm, "Update", "AllowAutoUpdate_ProviderSet") == null, "suffix values skipped");

            PolicySetting def = Find(s, Layers.Mdm, "Defender", "AllowRealtimeMonitoring");
            Check(def != null && def.Has(FindingKinds.Orphan) && def.Source == Sources.Unknown, "orphan detected");
            Check(def != null && def.Has(FindingKinds.Error), "error linked to setting");

            PolicySetting ts = Find(s, Layers.Mdm, "ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS");
            Check(ts != null && ts.FriendlyName.StartsWith("Allow users to connect remotely"), "ADMX-backed friendly name");
            Check(ts != null && ts.Has(FindingKinds.Conflict), "MDM side of conflict");
            PolicySetting tsg = Find(s, Layers.Registry, @"Microsoft\Windows NT\Terminal Services", "fDenyTSConnections");
            Check(tsg != null && tsg.Source == Sources.GroupPolicy && tsg.SourceDetail == "Baseline - RDP", "GPO winner from RSoP");
            Check(tsg != null && tsg.Contributions.Count == 2 && tsg.Contributions[0].Wins && !tsg.Contributions[1].Wins, "GPO precedence");
            Check(tsg != null && tsg.Has(FindingKinds.Conflict), "GPO side of conflict");

            PolicySetting au = Find(s, Layers.Registry, @"Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            Check(au != null && au.Has(FindingKinds.Conflict) && au.Findings[0].Message.Contains("Update area"), "area overlap");

            PolicySetting od = Find(s, Layers.Registry, @"Microsoft\OneDrive", "KFMSilentOptIn");
            Check(od != null && od.Source == Sources.MdmAdmx && od.SourceDetail == "OneDriveNGSCv2~Policy~OneDriveNGSC/KFMSilentOptIn", "ingested ADMX owns registry value");
            Check(od != null && od.FriendlyName == "Silently move Windows known folders to OneDrive", "element value name mapping");

            PolicySetting left = Find(s, Layers.Registry, @"Microsoft\Leftover", "Foo");
            Check(left != null && left.Has(FindingKinds.Unmanaged) && left.Source == Sources.Unmanaged, "unmanaged value");

            PolicySetting usr = Find(s, Layers.Mdm, "Start", "HideRecentlyAddedApps");
            Check(usr != null && usr.Scope == "User" && usr.UserSid == UserSid && usr.Source == Sources.Intune, "user scope MDM");
            PolicySetting office = Find(s, Layers.Registry, @"Microsoft\Office", "Bar");
            Check(office != null && office.Scope == "User" && office.Source == Sources.Unknown && !office.Has(FindingKinds.Unmanaged), "user registry not flagged");

            Check(s.Errors.Count == 2 && s.Errors[0].Area == "Defender" && s.Errors[0].Result == "The parameter is incorrect.", "event parsed");
            Check(s.Errors[1].CspUri == null && s.Errors[1].Result == "0x80070057", "event without URI");
            Check(s.PolicyRegistry.Count == 5, "raw registry dump");

            // RSoP missing: no Unmanaged findings, owner unknown.
            FakeRsop none = new FakeRsop();
            none.Note = "Resultant Set of Policy needs administrator rights.";
            CollectOptions o2 = new CollectOptions();
            o2.CurrentUserSid = UserSid;
            Snapshot s2 = Collector.Collect(SampleRegistry(), none, null, SampleCatalog(), o2);
            Check(!s2.RsopAvailable && s2.Count(FindingKinds.Unmanaged) == 0, "no unmanaged without RSoP");
            PolicySetting left2 = Find(s2, Layers.Registry, @"Microsoft\Leftover", "Foo");
            Check(left2 != null && left2.Source == Sources.Unknown, "unknown owner without RSoP");

            // JSON round trip.
            string dir = Path.Combine(Path.GetTempPath(), "policyvice-tests");
            Directory.CreateDirectory(dir);
            string json = Path.Combine(dir, "snap.json");
            s.Save(json);
            Snapshot back = Snapshot.Load(json);
            Check(back.Settings.Count == s.Settings.Count && back.Computer == "PC-0042", "JSON round trip");
            Check(Differ.Compare(s, back).Count == 0, "no diff after round trip");
            bool rejected = false;
            File.WriteAllText(Path.Combine(dir, "bad.json"), "{\"Tool\":\"Other\"}");
            try { Snapshot.Load(Path.Combine(dir, "bad.json")); } catch (InvalidDataException) { rejected = true; }
            Check(rejected, "foreign JSON rejected");

            // Diff.
            FakeRegistry r3 = SampleRegistry();
            r3.Set(@"HKLM\SOFTWARE\Policies\Microsoft\Leftover", "Foo", "REG_DWORD", "2");
            r3.Set(@"HKLM\SOFTWARE\Policies\Microsoft\New", "Baz", "REG_DWORD", "1");
            CollectOptions o3 = new CollectOptions();
            o3.CurrentUserSid = UserSid;
            Snapshot s3 = Collector.Collect(r3, SampleRsop(), null, SampleCatalog(), o3);
            s3.Settings.RemoveAll(delegate (PolicySetting p) { return p.Area.Contains("OneDrive"); });
            List<Change> d = Differ.Compare(s, s3);
            int added = 0, removed = 0, changed = 0;
            foreach (Change c in d)
            {
                if (c.Kind == Differ.Added) added++;
                if (c.Kind == Differ.Removed) removed++;
                if (c.Kind == Differ.Changed) changed++;
            }
            Check(added == 1 && removed == 2 && changed == 1, "diff counts " + added + "/" + removed + "/" + changed);

            List<Change> one = new List<Change>();
            Change ch = new Change();
            ch.Time = new DateTime(2026, 11, 8, 10, 1, 0);
            one.Add(ch);
            Differ.AttachEvents(one, s.Errors, TimeSpan.FromMinutes(2));
            Check(one[0].Events.Count == 2, "events attached to change");

            // Exports.
            string html = Report.Html(s);
            Check(html.Contains("PC-0042") && html.Contains("Baseline - RDP") && html.Contains("Findings"), "HTML report");
            Check(!html.Contains("<enabled/>") && html.Contains("&lt;enabled/&gt;"), "HTML encoded");
            string csv = Path.Combine(dir, "out.csv");
            Report.Csv(s, csv);
            string[] lines = File.ReadAllLines(csv);
            Check(lines.Length == s.Settings.Count + 1, "CSV rows");
            Check(Report.DiffHtml("a", "b", d, "0.1.0").Contains("Removed"), "diff HTML");

            Check(Txt.SplitCamel("TS_DISABLE_CONNECTIONS") == "TS DISABLE CONNECTIONS", "underscore split");
            Check(Txt.SplitCamel("AllowWindowsInkWorkspace") == "Allow Windows Ink Workspace", "camel split");
            Check(Txt.SplitCamel("DOHPolicy") == "DOH Policy", "acronym split");

            MdmError ue = new MdmError();
            ue.CspUri = "./User/Vendor/MSFT/Policy/Config/Start/HideRecentlyAddedApps";
            Collector.ParseUri(ue);
            Check(ue.Scope == "User" && ue.Area == "Start" && ue.Name == "HideRecentlyAddedApps", "user URI parsed");

            if (args.Length > 0) File.WriteAllText(args[0], html);
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }
    }
}
