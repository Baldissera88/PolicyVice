namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Text;

    // One Policy CSP setting from Microsoft's documentation: its friendly name, allowed values and Group Policy counterpart.
    public sealed class CspEntry
    {
        public string Area;
        public string Name;
        public string FriendlyName;
        public string Description;
        // Device, User or Both, from the OMA-URIs in the documentation.
        public string Scope;
        public string AdmxFile;
        public string AdmxPolicy;
        public string GpKey;
        public string GpValueName;
        public Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // The allowed values in the order of the documentation.
        public List<string> ValueOrder = new List<string>();
        // int, chr (string), bool, b64 and so on.
        public string Format;
        public string Default;
        // The range of allowed values, such as 0-365, when the documentation gives one.
        public string Range;
        // True for ADMX-backed settings, which take <enabled/> or <disabled/> with data elements.
        public bool AdmxBacked;
        // Group Policy path, such as Windows Components > Windows Update > Manage end user experience.
        public string GpPath;
        // Computer Configuration, User Configuration, or Computer and User Configuration.
        public string GpLocation;
        // The element of the Group Policy setting this value maps to, when the policy has several.
        public string GpElement;

        public string Uri
        {
            get { return "Policy/Config/" + Area + "/" + Name; }
        }

        public bool AppliesTo(string scope)
        {
            if (string.IsNullOrEmpty(Scope) || string.IsNullOrEmpty(scope)) return false;
            return string.Equals(Scope, "Both", StringComparison.OrdinalIgnoreCase) || string.Equals(Scope, scope, StringComparison.OrdinalIgnoreCase);
        }
    }

    // The offline Policy CSP catalog built by tools/build_csp_catalog.py from Microsoft's Policy CSP documentation (res/PolicyCsp.tsv.gz).
    public sealed class CspCatalog
    {
        public const string ResourceName = "PolicyCsp.tsv.gz";

        static readonly object Gate = new object();
        static CspCatalog embedded;

        readonly Dictionary<string, CspEntry> entries = new Dictionary<string, CspEntry>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, List<CspEntry>> byKey = new Dictionary<string, List<CspEntry>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, List<CspEntry>> byAdmx = new Dictionary<string, List<CspEntry>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly List<CspEntry> list = new List<CspEntry>();

        public int Count
        {
            get { return entries.Count; }
        }

        public IList<CspEntry> Entries
        {
            get { return list.AsReadOnly(); }
        }

        // The documentation commit the catalog was built from, such as 30fa38219c45...
        public string Commit
        {
            get { return Meta("commit"); }
        }

        // The date of that commit, yyyy-MM-dd.
        public string Date
        {
            get { return Meta("date"); }
        }

        // Where the catalog comes from, for the About box and reports.
        public string Source
        {
            get
            {
                if (Count == 0) return "No Policy CSP catalog";
                StringBuilder b = new StringBuilder("Microsoft Policy CSP documentation");
                string repo = Meta("source");
                if (string.IsNullOrEmpty(repo)) repo = Meta("upstream");
                if (!string.IsNullOrEmpty(repo)) b.Append(", ").Append(repo.Replace("https://", ""));
                string c = Commit;
                if (!string.IsNullOrEmpty(c)) b.Append(" commit ").Append(c.Length > 12 ? c.Substring(0, 12) : c);
                if (!string.IsNullOrEmpty(Date)) b.Append(" (").Append(Date).Append(")");
                string license = Meta("license");
                if (!string.IsNullOrEmpty(license)) b.Append(", ").Append(license);
                return b.ToString();
            }
        }

        // A value from the catalog header: format, upstream, source, branch, commit, date, license or entries.
        public string Meta(string key)
        {
            string v;
            return key != null && meta.TryGetValue(key, out v) ? v : null;
        }

        // The catalog embedded in the exe. Loaded once; empty when the resource is missing or cannot be read.
        public static CspCatalog Embedded()
        {
            lock (Gate)
            {
                if (embedded != null) return embedded;
                CspCatalog c = null;
                try
                {
                    using (Stream s = typeof(CspCatalog).Assembly.GetManifestResourceStream(ResourceName))
                    {
                        if (s != null) c = Load(s);
                    }
                }
                catch (Exception) { c = null; }
                embedded = c ?? new CspCatalog();
                return embedded;
            }
        }

        // Reads a gzip-compressed catalog. Never throws: a stream that cannot be read gives the rows read so far, or an empty catalog.
        public static CspCatalog Load(Stream stream)
        {
            CspCatalog c = new CspCatalog();
            if (stream == null) return c;
            try
            {
                using (GZipStream gz = new GZipStream(stream, CompressionMode.Decompress, true))
                using (StreamReader r = new StreamReader(gz, new UTF8Encoding(false), true))
                {
                    c.Read(r);
                }
            }
            catch (Exception) { }
            return c;
        }

        void Read(TextReader r)
        {
            Dictionary<string, int> col = null;
            string line;
            while ((line = r.ReadLine()) != null)
            {
                if (line.Length == 0) continue;
                if (col == null && line[0] == '#')
                {
                    int t = line.IndexOf('\t');
                    if (t > 1) meta[line.Substring(1, t - 1)] = Unescape(line.Substring(t + 1));
                    continue;
                }
                string[] cells = line.Split('\t');
                if (col == null)
                {
                    col = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < cells.Length; i++) col[cells[i].Trim()] = i;
                    if (!col.ContainsKey("Area") || !col.ContainsKey("Name")) return;
                    continue;
                }
                CspEntry e = new CspEntry();
                e.Area = Cell(cells, col, "Area");
                e.Name = Cell(cells, col, "Name");
                if (string.IsNullOrEmpty(e.Area) || string.IsNullOrEmpty(e.Name)) continue;
                e.Scope = Cell(cells, col, "Scope");
                e.FriendlyName = Cell(cells, col, "FriendlyName");
                e.Description = Cell(cells, col, "Description");
                e.Format = Cell(cells, col, "Format");
                e.Default = Cell(cells, col, "Default");
                e.Range = Cell(cells, col, "Range");
                e.AdmxBacked = Cell(cells, col, "AdmxBacked") == "1";
                e.AdmxFile = Cell(cells, col, "AdmxFile");
                e.AdmxPolicy = Cell(cells, col, "AdmxPolicy");
                e.GpPath = Cell(cells, col, "GpPath");
                e.GpLocation = Cell(cells, col, "GpLocation");
                e.GpElement = Cell(cells, col, "GpElement");
                e.GpKey = Cell(cells, col, "GpKey");
                e.GpValueName = Cell(cells, col, "GpValueName");
                string values = Cell(cells, col, "Values");
                if (!string.IsNullOrEmpty(values))
                {
                    foreach (string pair in values.Split('\n'))
                    {
                        int t = pair.IndexOf('\t');
                        string k = t < 0 ? pair : pair.Substring(0, t);
                        if (k.Length == 0 || e.Values.ContainsKey(k)) continue;
                        e.Values[k] = t < 0 ? "" : pair.Substring(t + 1);
                        e.ValueOrder.Add(k);
                    }
                }
                Add(e);
            }
        }

        void Add(CspEntry e)
        {
            string id = e.Area + "/" + e.Name;
            if (entries.ContainsKey(id)) return;
            entries[id] = e;
            list.Add(e);
            if (!string.IsNullOrEmpty(e.GpKey)) Index(byKey, NormKey(e.GpKey), e);
            if (!string.IsNullOrEmpty(e.AdmxFile) && !string.IsNullOrEmpty(e.AdmxPolicy)) Index(byAdmx, NormAdmx(e.AdmxFile) + "|" + e.AdmxPolicy, e);
        }

        static void Index(Dictionary<string, List<CspEntry>> map, string key, CspEntry e)
        {
            List<CspEntry> l;
            if (!map.TryGetValue(key, out l))
            {
                l = new List<CspEntry>();
                map[key] = l;
            }
            l.Add(e);
        }

        static string Cell(string[] cells, Dictionary<string, int> col, string name)
        {
            int i;
            if (!col.TryGetValue(name, out i) || i >= cells.Length) return null;
            string s = Unescape(cells[i]);
            return s.Length == 0 ? null : s;
        }

        static string Unescape(string s)
        {
            if (s.IndexOf('\\') < 0) return s;
            StringBuilder b = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c != '\\' || i + 1 >= s.Length)
                {
                    b.Append(c);
                    continue;
                }
                char n = s[++i];
                if (n == 't') b.Append('\t');
                else if (n == 'n') b.Append('\n');
                else if (n == 'r') b.Append('\r');
                else b.Append(n);
            }
            return b.ToString();
        }

        public CspEntry Find(string area, string name)
        {
            CspEntry e;
            return area != null && name != null && entries.TryGetValue(area + "/" + name, out e) ? e : null;
        }

        // The Policy CSP settings whose Group Policy counterpart writes this registry value. The key may start with a hive
        // (HKLM\, HKCU\, HKEY_LOCAL_MACHINE\, HKEY_CURRENT_USER\, HKU\<SID>\) and is compared without regard to case.
        // A null value name returns every setting documented under the key.
        public List<CspEntry> FindByRegistry(string key, string valueName)
        {
            List<CspEntry> found = new List<CspEntry>();
            List<CspEntry> l;
            if (string.IsNullOrEmpty(key) || !byKey.TryGetValue(NormKey(key), out l)) return found;
            foreach (CspEntry e in l)
                if (valueName == null || string.Equals(e.GpValueName, valueName, StringComparison.OrdinalIgnoreCase)) found.Add(e);
            return found;
        }

        // The Policy CSP settings that map to an ADMX policy, such as WindowsUpdate.admx (or WindowsUpdate) and AutoUpdateCfg.
        // Use it with AdmxCatalog.ForValue when the documentation gives the registry key but not the value name.
        public List<CspEntry> FindByAdmx(string admxFile, string policyName)
        {
            List<CspEntry> l;
            if (string.IsNullOrEmpty(admxFile) || string.IsNullOrEmpty(policyName) || !byAdmx.TryGetValue(NormAdmx(admxFile) + "|" + policyName, out l))
                return new List<CspEntry>();
            return new List<CspEntry>(l);
        }

        // A registry key without its hive, such as SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU.
        public static string NormKey(string key)
        {
            if (key == null) return "";
            string k = key.Trim().Trim('\\');
            string[] hives = { "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\", "HKLM\\", "HKCU\\", "Registry::" };
            bool again = true;
            while (again)
            {
                again = false;
                foreach (string h in hives)
                {
                    if (!k.StartsWith(h, StringComparison.OrdinalIgnoreCase)) continue;
                    k = k.Substring(h.Length).TrimStart('\\');
                    again = true;
                }
                foreach (string h in new string[] { "HKEY_USERS\\", "HKU\\" })
                {
                    if (!k.StartsWith(h, StringComparison.OrdinalIgnoreCase)) continue;
                    int i = k.IndexOf('\\', h.Length);
                    k = i < 0 ? "" : k.Substring(i + 1);
                    again = true;
                }
            }
            while (k.IndexOf("\\\\", StringComparison.Ordinal) >= 0) k = k.Replace("\\\\", "\\");
            return k.ToLowerInvariant();
        }

        static string NormAdmx(string file)
        {
            string f = file.Trim();
            if (f.EndsWith(".admx", StringComparison.OrdinalIgnoreCase)) f = f.Substring(0, f.Length - 5);
            return f.ToLowerInvariant();
        }

        // The value with its meaning, such as "1 (Allowed)", or the value as is when the meaning is not known.
        public static string Describe(CspEntry e, string value)
        {
            if (e == null || value == null) return value;
            string m = Meaning(e, value);
            return string.IsNullOrEmpty(m) ? value : value + " (" + m + ")";
        }

        // The documented meaning of a value, without a final full stop, or null.
        public static string Meaning(CspEntry e, string value)
        {
            if (e == null || value == null) return null;
            string m;
            string v = value.Trim();
            if (!e.Values.TryGetValue(v, out m))
            {
                long n;
                if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && long.TryParse(v.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out n)) v = n.ToString(CultureInfo.InvariantCulture);
                else if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n)) v = n.ToString(CultureInfo.InvariantCulture);
                if (!e.Values.TryGetValue(v, out m)) return null;
            }
            if (string.IsNullOrEmpty(m)) return null;
            m = m.Trim();
            if (m.EndsWith(".", StringComparison.Ordinal) && m.IndexOf(". ", StringComparison.Ordinal) < 0) m = m.Substring(0, m.Length - 1);
            return m;
        }
    }
}
