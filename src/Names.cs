namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Text.RegularExpressions;

    // Readable names for what Windows stores as SIDs, object IDs and codes.
    public static class Names
    {
        static readonly Regex RxGuid = new Regex(@"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$", RegexOptions.Compiled);
        static readonly Regex RxData = new Regex("<data\\s+id=\"([^\"]*)\"\\s+value=\"([^\"]*)\"\\s*/>", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxVersion = new Regex(@"v\d+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static bool IsGuid(string s)
        {
            return !string.IsNullOrEmpty(s) && RxGuid.IsMatch(s.Trim());
        }

        // The SID Windows gives a Microsoft Entra user: S-1-12-1 followed by the object ID as four numbers.
        public static string SidFromObjectId(string objectId)
        {
            if (!IsGuid(objectId)) return null;
            byte[] b = new Guid(objectId.Trim('{', '}')).ToByteArray();
            StringBuilder s = new StringBuilder("S-1-12-1");
            for (int i = 0; i < 16; i += 4) s.Append('-').Append(BitConverter.ToUInt32(b, i).ToString(CultureInfo.InvariantCulture));
            return s.ToString();
        }

        // User names by SID, from the enrollments, the Windows sign-in cache and the user profiles.
        public sealed class Users
        {
            readonly IRegSource reg;
            readonly Dictionary<string, string> known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            public Users(IRegSource reg, Snapshot s)
            {
                this.reg = reg;
                if (reg == null) return;
                try
                {
                    foreach (string id in reg.SubKeys(Collector.Enrollments))
                    {
                        RegValue sid = reg.Get(Collector.Enrollments + "\\" + id, "SID");
                        RegValue upn = reg.Get(Collector.Enrollments + "\\" + id, "UPN");
                        if (sid != null && upn != null && !string.IsNullOrEmpty(sid.Data) && !string.IsNullOrEmpty(upn.Data)) known[sid.Data] = upn.Data;
                    }
                }
                catch (Exception) { }
            }

            public string Name(string sid)
            {
                if (string.IsNullOrEmpty(sid) || reg == null) return null;
                string n;
                if (known.TryGetValue(sid, out n)) return n;
                n = null;
                try
                {
                    RegValue v = reg.Get(@"HKLM\SOFTWARE\Microsoft\IdentityStore\Cache\" + sid + @"\IdentityCache\" + sid, "UserName");
                    if (v != null && !string.IsNullOrEmpty(v.Data)) n = v.Data;
                    if (n == null)
                    {
                        RegValue p = reg.Get(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid, "ProfileImagePath");
                        if (p != null && !string.IsNullOrEmpty(p.Data)) n = p.Data.TrimEnd('\\').Substring(p.Data.TrimEnd('\\').LastIndexOf('\\') + 1);
                    }
                }
                catch (Exception) { }
                known[sid] = n;
                return n;
            }

            // A user object ID from the Intune Management Extension, as a name when the user has signed in here.
            public string NameForObjectId(string objectId)
            {
                return Name(SidFromObjectId(objectId));
            }
        }

        // A readable MDM area: ADMX_TerminalServer becomes "Terminal Server (ADMX)",
        // office16v2~Policy~L_MicrosoftOfficeSystem~L_SecuritySettings becomes "Office 16: Microsoft Office System > Security Settings".
        public static string Area(string area)
        {
            if (string.IsNullOrEmpty(area)) return area;
            if (area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase)) return Txt.SplitCamel(area.Substring(5)) + " (ADMX)";
            int i = area.IndexOf("~Policy~", StringComparison.OrdinalIgnoreCase);
            if (i > 0)
            {
                string app = App(area.Substring(0, i));
                List<string> parts = new List<string>();
                foreach (string p in area.Substring(i + 8).Split('~'))
                {
                    if (p.Length == 0) continue;
                    string q = p.StartsWith("L_", StringComparison.Ordinal) ? p.Substring(2) : p;
                    parts.Add(Txt.SplitCamel(q));
                }
                return app + (parts.Count > 0 ? ": " + string.Join(" > ", parts.ToArray()) : "");
            }
            return Txt.SplitCamel(area);
        }

        static string App(string app)
        {
            string a = RxVersion.Replace(app, "");
            switch (a.ToLowerInvariant())
            {
                case "onedrivengsc": return "OneDrive";
                case "office16": return "Office 16";
                case "msedge":
                case "microsoftedge": return "Microsoft Edge";
                case "chromeintune": return "Google Chrome";
                default: return Txt.SplitCamel(a);
            }
        }

        // An ADMX-backed value in words: "<enabled/><data id="KFMSilentOptInBox" value="x"/>" becomes "Enabled, KFM Silent Opt In Box: x".
        public static string AdmxValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            string t = value.TrimStart();
            bool on = t.StartsWith("<enabled", StringComparison.OrdinalIgnoreCase);
            if (!on && !t.StartsWith("<disabled", StringComparison.OrdinalIgnoreCase)) return null;
            StringBuilder b = new StringBuilder(on ? "Enabled" : "Disabled");
            foreach (Match m in RxData.Matches(value))
            {
                string v = WebUtility.HtmlDecode(m.Groups[2].Value).Replace("\uF000", ", ").Trim(',', ' ');
                b.Append(", ").Append(Txt.SplitCamel(m.Groups[1].Value)).Append(": ").Append(v);
            }
            return b.ToString();
        }
    }

    // Names of Intune apps, scripts and remediations from Microsoft Graph, kept per tenant so they show offline.
    public static class NameCache
    {
        public static string Folder
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PolicyVice"); }
        }

        static string FileFor(string tenant)
        {
            string t = string.IsNullOrEmpty(tenant) ? "default" : Regex.Replace(tenant, "[^0-9A-Za-z-]", "");
            return Path.Combine(Folder, "IntuneNames-" + t + ".tsv");
        }

        public static Dictionary<string, string> Load(string tenant)
        {
            return LoadFile(FileFor(tenant));
        }

        public static Dictionary<string, string> LoadFile(string path)
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(path)) return d;
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    int tab = line.IndexOf('\t');
                    if (tab <= 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                    d[line.Substring(0, tab)] = line.Substring(tab + 1);
                }
            }
            catch (Exception) { }
            return d;
        }

        public static DateTime? Updated(string tenant)
        {
            try
            {
                string p = FileFor(tenant);
                return File.Exists(p) ? (DateTime?)File.GetLastWriteTime(p) : null;
            }
            catch (Exception) { return null; }
        }

        public static void Save(string tenant, Dictionary<string, string> names)
        {
            SaveFile(FileFor(tenant), names);
        }

        public static void SaveFile(string path, Dictionary<string, string> names)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            StringBuilder b = new StringBuilder("# Names of Intune apps, scripts and remediations, from Microsoft Graph\r\n");
            foreach (KeyValuePair<string, string> kv in names)
                b.Append(kv.Key).Append('\t').Append((kv.Value ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ')).Append("\r\n");
            File.WriteAllText(path, b.ToString(), new UTF8Encoding(false));
        }

        public static void Delete(string tenant)
        {
            try { File.Delete(FileFor(tenant)); } catch (Exception) { }
        }

        // Fills in names from the cache. Graph names replace names from the logs, which can be out of date.
        public static int Apply(List<ImeItem> items, Dictionary<string, string> names)
        {
            if (items == null || names == null || names.Count == 0) return 0;
            int n = 0;
            foreach (ImeItem it in items)
            {
                if (string.IsNullOrEmpty(it.Id)) continue;
                string id = it.Id.Trim('{', '}');
                int us = id.IndexOf('_');
                if (us > 0) id = id.Substring(0, us);
                string name;
                if (names.TryGetValue(id, out name) && !string.IsNullOrEmpty(name))
                {
                    it.Name = name;
                    n++;
                }
            }
            return n;
        }
    }
}
