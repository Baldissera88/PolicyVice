namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    public sealed class FakeRegistry : IRegSource
    {
        readonly Dictionary<string, Dictionary<string, RegValue>> keys = new Dictionary<string, Dictionary<string, RegValue>>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> denied = new List<string>();
        readonly Dictionary<string, bool> blocked = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public List<string> Denied
        {
            get { return denied; }
        }

        // The key exists but cannot be opened, like a key without read access.
        public void Block(string path)
        {
            Ensure(path);
            blocked[path] = true;
        }

        bool IsBlocked(string path)
        {
            if (!blocked.ContainsKey(path)) return false;
            if (!denied.Contains(path)) denied.Add(path);
            return true;
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
            if (IsBlocked(path)) return new string[0];
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
            if (IsBlocked(path)) return new string[0];
            if (!keys.TryGetValue(path, out v)) return new string[0];
            return new List<string>(v.Keys).ToArray();
        }

        public RegValue Get(string path, string name)
        {
            Dictionary<string, RegValue> v;
            RegValue r;
            if (IsBlocked(path)) return null;
            return keys.TryGetValue(path, out v) && v.TryGetValue(name, out r) ? r : null;
        }
    }

    public sealed class FakeRsop : IRsopSource, IUserRsopSource
    {
        public List<RsopValue> Values = new List<RsopValue>();
        public string Note;
        public Dictionary<string, List<RsopValue>> Users = new Dictionary<string, List<RsopValue>>(StringComparer.OrdinalIgnoreCase);
        public bool Throw;
        public List<string> UserCalls = new List<string>();

        public List<RsopValue> ComputerValues(out string note)
        {
            if (Throw) throw new InvalidOperationException("WMI is broken");
            note = Note;
            return Values;
        }

        public List<RsopValue> UserValues(string sid, out string note)
        {
            UserCalls.Add(sid);
            if (Throw) throw new InvalidOperationException("WMI is broken");
            List<RsopValue> l;
            if (sid != null && Users.TryGetValue(sid, out l))
            {
                note = null;
                return l;
            }
            note = "There is no user Resultant Set of Policy for this user.";
            return new List<RsopValue>();
        }

        public void AddUser(string sid, string key, string name, string data, string gpo, int prec)
        {
            List<RsopValue> l;
            if (!Users.TryGetValue(sid, out l)) { l = new List<RsopValue>(); Users[sid] = l; }
            RsopValue r = new RsopValue();
            r.Key = key;
            r.ValueName = name;
            r.Data = data;
            r.Kind = "REG_SZ";
            r.GpoName = gpo;
            r.GpoId = "CN={" + gpo + "},CN=Policies,CN=System,DC=contoso,DC=com";
            r.Precedence = prec;
            l.Add(r);
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

    public sealed class FakeEvents : IEventSource, ISourceNote
    {
        public List<EventItem> Items = new List<EventItem>();
        public bool Throw;
        public string ReadNote;

        public string Note
        {
            get { return ReadNote; }
        }

        public List<EventItem> Read(string channel, DateTime since, bool errorsOnly)
        {
            if (Throw) throw new UnauthorizedAccessException("Access is denied.");
            return Items;
        }

        public EventItem Add(int id, string level, string message, params string[] props)
        {
            EventItem i = new EventItem();
            i.Time = new DateTime(2026, 11, 8, 9, 0, 0);
            i.Id = id;
            i.Level = level;
            i.Message = message;
            i.Properties = props;
            Items.Add(i);
            return i;
        }
    }

    public static class CoreTests
    {

        const string IntuneId = "3A1B2C3D-0000-4000-8000-000000000001";
        const string Pm = @"HKLM\SOFTWARE\Microsoft\PolicyManager";
        const string UserSid = "S-1-12-1-1111-2222-3333-4444";

        static void Check(bool ok, string what)
        {
            T.Check(ok, "core: " + what);
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

        public static void Run(string[] args)
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

            Hardening();
            Events();

            if (args.Length > 0) File.WriteAllText(args[0], html);
        }

        static CollectOptions Opt()
        {
            CollectOptions o = new CollectOptions();
            o.CurrentUserSid = UserSid;
            o.NowUtc = new DateTime(2026, 11, 8, 9, 30, 0, DateTimeKind.Utc);
            return o;
        }

        static bool HasNote(Snapshot s, string part)
        {
            foreach (string n in s.Notes) if (n.Contains(part)) return true;
            return false;
        }

        static void Hardening()
        {
            // A provider GUID that is not an enrollment is not called MDM.
            const string Other = "77777777-0000-4000-8000-000000000007";
            FakeRegistry r = SampleRegistry();
            string priv = Pm + @"\current\device\Privacy";
            r.Set(priv, "LetAppsAccessCamera", "REG_DWORD", "2");
            r.Set(priv, "LetAppsAccessCamera_ProviderSet", "REG_DWORD", "1");
            r.Set(priv, "LetAppsAccessCamera_WinningProvider", "REG_SZ", Other);
            r.Set(priv, "LetAppsAccessCamera_LastWrite", "REG_DWORD", "1");
            r.Set(priv, "LetAppsAccessCamera_ADMXInstanceData", "REG_SZ", "x");
            r.Set(Pm + @"\providers\" + Other + @"\default\Device\Privacy", "LetAppsAccessCamera", "REG_DWORD", "2");
            r.Set(Pm + @"\providers\" + Other + @"\default\Device\Privacy", "LetAppsAccessCamera_LastWrite", "REG_DWORD", "1");
            // Not enrollments: no ProviderID.
            r.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\Status", "x", "REG_DWORD", "0");
            r.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\ValidNodePaths", "x", "REG_DWORD", "0");
            Snapshot s = Collector.Collect(r, SampleRsop(), null, SampleCatalog(), Opt());
            PolicySetting cam = Find(s, Layers.Mdm, "Privacy", "LetAppsAccessCamera");
            Check(cam != null && cam.Source == Sources.Unknown && cam.SourceDetail.Contains("not an MDM enrollment") && !cam.Has(FindingKinds.Orphan), "unknown provider is Unknown, not Other MDM");
            Check(cam != null && cam.Contributions.Count == 1 && cam.Contributions[0].Source == Sources.Unknown && cam.Contributions[0].Wins, "unknown provider contribution");
            int camCount = 0;
            foreach (PolicySetting p in s.Settings) if (p.Area == "Privacy") camCount++;
            Check(camCount == 1, "every companion suffix skipped");
            Check(s.Enrollments.Count == 1, "Status and ValidNodePaths are not enrollments");

            // Other MDM: an enrollment with another ProviderID, and a winner written with braces.
            FakeRegistry ro = SampleRegistry();
            ro.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\" + Other, "ProviderID", "REG_SZ", "AirWatchMDM");
            ro.Set(Pm + @"\current\device\Camera", "AllowCamera", "REG_DWORD", "0");
            ro.Set(Pm + @"\current\device\Camera", "AllowCamera_WinningProvider", "REG_SZ", "{" + Other + "}");
            ro.Set(Pm + @"\providers\" + Other + @"\default\Device\Camera", "AllowCamera", "REG_DWORD", "0");
            Snapshot so = Collector.Collect(ro, SampleRsop(), null, SampleCatalog(), Opt());
            PolicySetting camo = Find(so, Layers.Mdm, "Camera", "AllowCamera");
            Check(camo != null && camo.Source == Sources.OtherMdm && camo.SourceDetail == "AirWatchMDM", "other MDM enrollment");

            // A provider key that cannot be read: no orphan claims, a note and an access denied entry.
            FakeRegistry rd = SampleRegistry();
            string blocked = Pm + @"\providers\" + IntuneId + @"\default";
            rd.Block(blocked);
            Snapshot sd = Collector.Collect(rd, SampleRsop(), null, SampleCatalog(), Opt());
            Check(sd.Count(FindingKinds.Orphan) == 0, "no orphans when providers are unreadable");
            Check(sd.AccessDenied.Contains(blocked), "denied key recorded");
            Check(HasNote(sd, "orphaned MDM values are not reported"), "note for unreadable providers");
            Check(sd.Device.Items.Exists(delegate (InfoItem i) { return i.Group == "Collection"; }), "notes shown with device information");

            // User Group Policy from RSoP for HKCU and for another user in HKU.
            const string Sid2 = "S-1-5-21-1000-2000-3000-1104";
            FakeRegistry ru = SampleRegistry();
            ru.Set(@"HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Common", "QMEnable", "REG_DWORD", "0");
            ru.Set(Pm + @"\current\" + Sid2 + @"\Start", "HideRecentlyAddedApps", "REG_DWORD", "1");
            ru.Set(Pm + @"\providers\" + IntuneId + @"\default\" + Sid2 + @"\Start", "HideRecentlyAddedApps", "REG_DWORD", "1");
            ru.Set(@"HKU\" + Sid2 + @"\SOFTWARE\Policies\Microsoft\Edge", "HomepageLocation", "REG_SZ", "https://contoso.com");
            FakeRsop gu = SampleRsop();
            gu.AddUser(UserSid, @"Software\Policies\Microsoft\Office", "Bar", "baz", "User - Office", 1);
            gu.AddUser(UserSid, @"Software\Policies\Microsoft\Office", "Bar", "old", "User - Legacy", 2);
            Snapshot su = Collector.Collect(ru, gu, null, SampleCatalog(), Opt());
            PolicySetting bar = Find(su, Layers.Registry, @"Microsoft\Office", "Bar");
            Check(bar != null && bar.Source == Sources.GroupPolicy && bar.SourceDetail == "User - Office" && bar.UserSid == UserSid, "user GPO from user RSoP");
            Check(bar != null && bar.Contributions.Count == 2 && bar.Contributions[0].Wins && bar.Contributions[0].RegistryPath == @"HKCU\Software\Policies\Microsoft\Office", "user GPO precedence and path");
            PolicySetting qm = Find(su, Layers.Registry, @"Microsoft\Office\16.0\Common", "QMEnable");
            Check(qm != null && qm.Source == Sources.Unmanaged && qm.Has(FindingKinds.Unmanaged), "unclaimed user value with user RSoP");
            PolicySetting home = Find(su, Layers.Registry, @"Microsoft\Edge", "HomepageLocation");
            Check(home != null && home.Scope == "User" && home.UserSid == Sid2 && home.Source == Sources.Unknown && home.SourceDetail.StartsWith("User Group Policy not available"), "user without RSoP stays Unknown");
            Check(HasNote(su, Sid2), "note for user without RSoP");
            Check(gu.UserCalls.Count == 2 && gu.UserCalls.Contains(UserSid) && gu.UserCalls.Contains(Sid2), "user RSoP read once per user");

            // RSoP and events that throw do not stop the collection.
            FakeRsop bad = SampleRsop();
            bad.Throw = true;
            FakeEvents badEv = new FakeEvents();
            badEv.Throw = true;
            Snapshot sb = null;
            try { sb = Collector.Collect(SampleRegistry(), bad, badEv, SampleCatalog(), Opt()); } catch (Exception) { }
            Check(sb != null && !sb.RsopAvailable && sb.RsopNote.Contains("WMI is broken"), "RSoP exception becomes a note");
            Check(sb != null && HasNote(sb, "MDM events could not be read"), "event exception becomes a note");
            Check(sb != null && Find(sb, Layers.Mdm, "Update", "AllowAutoUpdate") != null && sb.Count(FindingKinds.Unmanaged) == 0, "other sources still read");
            PolicySetting bar2 = sb == null ? null : Find(sb, Layers.Registry, @"Microsoft\Office", "Bar");
            Check(bar2 != null && bar2.Source == Sources.Unknown, "user value Unknown when user RSoP throws");

            // A timed-out RSoP.
            FakeRsop slow = new FakeRsop();
            slow.Note = "Resultant Set of Policy did not answer within 45 seconds.";
            Snapshot st = Collector.Collect(SampleRegistry(), slow, null, SampleCatalog(), Opt());
            PolicySetting left = Find(st, Layers.Registry, @"Microsoft\Leftover", "Foo");
            Check(!st.RsopAvailable && st.RsopNote == slow.Note && left != null && left.Source == Sources.Unknown && !left.Has(FindingKinds.Unmanaged), "RSoP timeout note");

            // A large policy registry is capped with a note.
            FakeRegistry big = new FakeRegistry();
            for (int k = 0; k < 250; k++)
                for (int v = 0; v < 100; v++)
                    big.Set(@"HKLM\SOFTWARE\Policies\Vendor\App" + k, "V" + v, "REG_DWORD", "1");
            DateTime t0 = DateTime.UtcNow;
            Snapshot sbig = Collector.Collect(big, new FakeRsop(), null, null, Opt());
            Check(sbig.PolicyRegistry.Count == Collector.MaxRegistryValues && HasNote(sbig, @"values under SOFTWARE\Policies were read"), "registry budget " + sbig.PolicyRegistry.Count);
            Check((DateTime.UtcNow - t0).TotalSeconds < 30, "large registry in reasonable time");

            // What decides a conflict is stated without overclaiming.
            Snapshot sw = Sample();
            PolicySetting ts = Find(sw, Layers.Mdm, "ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS");
            Check(ts != null && ts.Findings[0].Message.Contains("only for Policy CSP settings that have an equivalent Group Policy"), "MDMWinsOverGP scope stated");
            PolicySetting au = Find(sw, Layers.Registry, @"Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            Check(au != null && au.Findings[0].Message.Contains("IgnoreWindowsUpdateGroupPolicies") && au.Findings[0].Message.Contains("not on"), "Update conflict names IgnoreWindowsUpdateGroupPolicies");
            FakeRegistry ri = SampleRegistry();
            ri.Set(Pm + @"\current\device\Update", "IgnoreWindowsUpdateGroupPolicies", "REG_DWORD", "1");
            Snapshot si = Collector.Collect(ri, SampleRsop(), null, SampleCatalog(), Opt());
            PolicySetting aui = Find(si, Layers.Registry, @"Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            Check(aui != null && aui.Findings[0].Message.Contains("IgnoreWindowsUpdateGroupPolicies is on"), "IgnoreWindowsUpdateGroupPolicies read");
            FakeRegistry rn = SampleRegistry();
            rn.Set(Pm + @"\current\device\ControlPolicyConflict", "MDMWinsOverGP", "REG_DWORD", "0");
            Snapshot sn = Collector.Collect(rn, SampleRsop(), null, SampleCatalog(), Opt());
            PolicySetting tsn = Find(sn, Layers.Mdm, "ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS");
            Check(!sn.MdmWinsOverGp && tsn != null && tsn.Findings[0].Message.Contains("no guarantee"), "MDMWinsOverGP off");
        }

        static void Events()
        {
            FakeEvents ev = new FakeEvents();
            // Message template missing: only the properties, in the order of the 404 template.
            EventItem raw = ev.Add(404, "Error", null, IntuneId, "MDMDeviceWithAAD", "Policy", "0x00000002", "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate", "0x80070057");
            raw.Message = string.Join(", ", raw.Properties);
            ev.Add(809, "Error", "MDM PolicyManager: Set policy int, Policy: (AllowTelemetry), Area: (System), EnrollmentID requesting set: (" + IntuneId + "), Current User: (Device), Int: (0x2AFE388), Enrollment Type: (0x6), Scope: (0x0), Result:(0x86000011) Unknown Win32 Error code: 0x86000011.");
            ev.Add(2545, "Error", "MDM Declared Configuration: Function (checkNewInstanceData) operation (Read isNewInstanceData) failed with (The parameter is incorrect.)", "checkNewInstanceData", "Read isNewInstanceData", "0x80070057");
            ev.Add(454, "Error", "MDM ConfigurationManager: Command failure status. Configuraton Source ID: {D9E3514D-4668-424B-A6B9-9B16B1C935BE}, Enrollment Type: FamilySafety, CSP Name: AppLocker, Command Type: Add: from Replace or Add, Result: ./Vendor/MSFT/AppLocker/FamilySafety/FamilySafetyGroup/StoreApps.");
            ev.Add(404, "Error", "MDM ConfigurationManager: Command failure status. Configuration Source ID: (" + IntuneId + "), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (defender), Command Type: (Add: from Replace or Add), CSP URI: (./vendor/msft/defender/configuration/devicecontrol/policyrules/{b7db918d-3702-4daa-865b-e71b45047c9e}/ruledata), Result: (The parameter is incorrect.).",
                IntuneId, "MDMDeviceWithAAD", "defender", "0x00000002", "./vendor/msft/defender/configuration/devicecontrol/policyrules/{b7db918d-3702-4daa-865b-e71b45047c9e}/ruledata", "0x80070057");
            ev.Add(809, "Error", "MDM PolicyManager: Set policy int, Policy: (HideRecentlyAddedApps), Area: (Start), EnrollmentID requesting set: (" + IntuneId + "), Current User: (" + UserSid + "), Int: (0x1), Enrollment Type: (0x6), Scope: (0x1), Result:(0x86000011).");
            ev.Add(404, "Error", null);
            ev.Add(404, "Error", "CSP URI: (), Result: ()");
            ev.Items.Add(null);
            ev.ReadNote = "Only the newest 5000 events were read.";
            Snapshot s = Collector.Collect(SampleRegistry(), SampleRsop(), ev, SampleCatalog(), Opt());
            Check(s.Errors.Count == 8, "all events kept " + s.Errors.Count);
            MdmError a = s.Errors[0];
            Check(a.CspUri == "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate" && a.Area == "Update" && a.Result == "0x80070057", "event without template parsed from properties");
            PolicySetting upd = Find(s, Layers.Mdm, "Update", "AllowAutoUpdate");
            Check(upd != null && upd.Has(FindingKinds.Error), "property event linked to setting");
            MdmError b = s.Errors[1];
            Check(b.Area == "System" && b.Name == "AllowTelemetry" && b.Scope == "Device" && b.Result == "0x86000011" && b.CspUri == "./Device/Vendor/MSFT/Policy/Config/System/AllowTelemetry", "PolicyManager event parsed");
            MdmError c = s.Errors[2];
            Check(c.CspUri == null && c.Area == null && c.Result == "0x80070057", "event 2545 result from properties");
            MdmError d = s.Errors[3];
            Check(d.CspUri == "./Vendor/MSFT/AppLocker/FamilySafety/FamilySafetyGroup/StoreApps" && d.Area == null, "old 454 format");
            MdmError e = s.Errors[4];
            Check(e.CspUri != null && e.CspUri.StartsWith("./vendor/msft/defender/") && e.Result == "The parameter is incorrect. (0x80070057)" && e.Area == null, "text result with HRESULT");
            MdmError f = s.Errors[5];
            Check(f.Scope == "User" && f.Area == "Start" && f.CspUri != null && f.CspUri.StartsWith("./User/"), "user PolicyManager event");
            PolicySetting usr = Find(s, Layers.Mdm, "Start", "HideRecentlyAddedApps");
            Check(usr != null && usr.Has(FindingKinds.Error), "user event linked");
            Check(s.Errors[6].CspUri == null && s.Errors[6].Result == null && s.Errors[7].CspUri == null && s.Errors[7].Result == null, "empty and malformed events");
            Check(HasNote(s, "newest 5000"), "event source note");
        }
    }
}
