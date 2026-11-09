namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Xml;

    public sealed class AdmxPolicy
    {
        public string File;
        public string Name;
        public string Class;
        public string Key;
        public string ValueName;
        public string DisplayName;
        public string Explain;
        public bool Ingested;
    }

    // Policy definitions from ADMX and ADML files: the Windows PolicyDefinitions folder and ADMX files ingested through MDM.
    public sealed class AdmxCatalog
    {
        readonly Dictionary<string, Dictionary<string, AdmxPolicy>> byFile = new Dictionary<string, Dictionary<string, AdmxPolicy>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, List<AdmxPolicy>> byName = new Dictionary<string, List<AdmxPolicy>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, AdmxPolicy> byValue = new Dictionary<string, AdmxPolicy>(StringComparer.OrdinalIgnoreCase);
        int count;

        public int Count
        {
            get { return count; }
        }

        public static string DefaultFolder
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "PolicyDefinitions"); }
        }

        public static string IngestionFolder
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\PolicyManager\ADMXIngestion"); }
        }

        public void LoadFolder(string dir)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            string[] files;
            try { files = Directory.GetFiles(dir, "*.admx"); }
            catch (Exception) { return; }
            foreach (string f in files)
            {
                try
                {
                    string admx = File.ReadAllText(f);
                    string adml = FindAdml(dir, Path.GetFileNameWithoutExtension(f));
                    Load(Path.GetFileNameWithoutExtension(f), admx, adml != null ? File.ReadAllText(adml) : null, false);
                }
                catch (Exception) { }
            }
        }

        public int LoadIngested(string dir)
        {
            int before = count;
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return 0;
            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch (Exception) { return 0; }
            foreach (string f in files)
            {
                try
                {
                    string text = File.ReadAllText(f);
                    if (text.IndexOf("<policyDefinitions", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    Load(Path.GetFileNameWithoutExtension(f), text, null, true);
                }
                catch (Exception) { }
            }
            return count - before;
        }

        static string FindAdml(string dir, string name)
        {
            List<string> cultures = new List<string>();
            try { cultures.Add(CultureInfo.CurrentUICulture.Name); } catch (Exception) { }
            cultures.Add("en-US");
            foreach (string c in cultures)
            {
                string p = Path.Combine(Path.Combine(dir, c), name + ".adml");
                if (File.Exists(p)) return p;
            }
            try
            {
                foreach (string sub in Directory.GetDirectories(dir))
                {
                    string p = Path.Combine(sub, name + ".adml");
                    if (File.Exists(p)) return p;
                }
            }
            catch (Exception) { }
            return null;
        }

        // Loads one ADMX text and its optional ADML text. Returns the number of policies added.
        public int Load(string fileName, string admx, string adml, bool ingested)
        {
            Dictionary<string, string> strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(adml))
            {
                XmlDocument d = Parse(adml);
                if (d != null)
                {
                    foreach (XmlNode n in d.GetElementsByTagName("string"))
                    {
                        XmlAttribute id = n.Attributes == null ? null : n.Attributes["id"];
                        if (id != null) strings[id.Value] = n.InnerText;
                    }
                }
            }
            XmlDocument doc = Parse(admx);
            if (doc == null) return 0;
            Dictionary<string, AdmxPolicy> file;
            if (!byFile.TryGetValue(fileName, out file))
            {
                file = new Dictionary<string, AdmxPolicy>(StringComparer.OrdinalIgnoreCase);
                byFile[fileName] = file;
            }
            int added = 0;
            foreach (XmlNode n in doc.GetElementsByTagName("policy"))
            {
                if (n.Attributes == null || n.Attributes["name"] == null) continue;
                AdmxPolicy p = new AdmxPolicy();
                p.File = fileName;
                p.Name = n.Attributes["name"].Value;
                p.Class = Attr(n, "class");
                p.Key = Attr(n, "key");
                p.ValueName = Attr(n, "valueName");
                p.DisplayName = Resolve(Attr(n, "displayName"), strings);
                p.Explain = Resolve(Attr(n, "explainText"), strings);
                p.Ingested = ingested;
                file[p.Name] = p;
                List<AdmxPolicy> same;
                if (!byName.TryGetValue(p.Name, out same))
                {
                    same = new List<AdmxPolicy>();
                    byName[p.Name] = same;
                }
                same.Add(p);
                if (!string.IsNullOrEmpty(p.Key) && !string.IsNullOrEmpty(p.ValueName)) Index(p.Key, p.ValueName, p);
                IndexChildren(n, p);
                added++;
                count++;
            }
            return added;
        }

        void IndexChildren(XmlNode node, AdmxPolicy p)
        {
            foreach (XmlNode c in node.ChildNodes)
            {
                if (c.NodeType != XmlNodeType.Element) continue;
                string vn = Attr(c, "valueName");
                if (!string.IsNullOrEmpty(vn))
                {
                    string key = Attr(c, "key");
                    Index(string.IsNullOrEmpty(key) ? p.Key : key, vn, p);
                }
                else if (c.LocalName == "list" && !string.IsNullOrEmpty(Attr(c, "key")))
                {
                    // A list writes numbered or named values under its own key.
                    Index(Attr(c, "key"), "*", p);
                }
                IndexChildren(c, p);
            }
        }

        void Index(string key, string valueName, AdmxPolicy p)
        {
            if (string.IsNullOrEmpty(key)) return;
            string k = Norm(key) + "|" + valueName;
            if (!byValue.ContainsKey(k)) byValue[k] = p;
        }

        static string Norm(string key)
        {
            string k = key.Trim('\\');
            foreach (string hive in new string[] { "HKLM\\", "HKCU\\", "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\" })
                if (k.StartsWith(hive, StringComparison.OrdinalIgnoreCase)) k = k.Substring(hive.Length);
            return k.ToLowerInvariant();
        }

        // The policy by ADMX file name (with or without .admx) and policy name.
        public AdmxPolicy Find(string admxFile, string policy)
        {
            if (string.IsNullOrEmpty(admxFile) || string.IsNullOrEmpty(policy)) return null;
            string f = admxFile.EndsWith(".admx", StringComparison.OrdinalIgnoreCase) ? admxFile.Substring(0, admxFile.Length - 5) : admxFile;
            Dictionary<string, AdmxPolicy> file;
            AdmxPolicy p;
            return byFile.TryGetValue(f, out file) && file.TryGetValue(policy, out p) ? p : null;
        }

        public bool HasFile(string fileName)
        {
            return !string.IsNullOrEmpty(fileName) && byFile.ContainsKey(fileName);
        }

        public AdmxPolicy ForValue(string key, string valueName)
        {
            AdmxPolicy p;
            string k = Norm(key);
            if (byValue.TryGetValue(k + "|" + valueName, out p)) return p;
            return byValue.TryGetValue(k + "|*", out p) ? p : null;
        }

        // Finds the ADMX policy behind an MDM setting, for ADMX-backed Policy CSP areas (ADMX_<file>) and ingested ADMX (<app>~Policy~<category>).
        public AdmxPolicy ForMdm(string area, string name)
        {
            if (string.IsNullOrEmpty(area) || string.IsNullOrEmpty(name)) return null;
            Dictionary<string, AdmxPolicy> file;
            AdmxPolicy p;
            if (area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase))
            {
                if (byFile.TryGetValue(area.Substring(5), out file) && file.TryGetValue(name, out p)) return p;
                return null;
            }
            if (area.IndexOf("~Policy~", StringComparison.OrdinalIgnoreCase) > 0)
            {
                List<AdmxPolicy> same;
                if (!byName.TryGetValue(name, out same)) return null;
                foreach (AdmxPolicy q in same) if (q.Ingested) return q;
                return same.Count == 1 ? same[0] : null;
            }
            return null;
        }

        static XmlDocument Parse(string text)
        {
            try
            {
                XmlDocument d = new XmlDocument();
                d.XmlResolver = null;
                XmlReaderSettings s = new XmlReaderSettings();
                s.DtdProcessing = DtdProcessing.Prohibit;
                s.XmlResolver = null;
                using (XmlReader r = XmlReader.Create(new StringReader(text.TrimStart('﻿')), s))
                {
                    d.Load(r);
                }
                return d;
            }
            catch (Exception) { return null; }
        }

        static string Attr(XmlNode n, string name)
        {
            if (n.Attributes == null) return null;
            XmlAttribute a = n.Attributes[name];
            return a == null ? null : a.Value;
        }

        static string Resolve(string s, Dictionary<string, string> strings)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.StartsWith("$(string.", StringComparison.Ordinal) && s.EndsWith(")", StringComparison.Ordinal))
            {
                string id = s.Substring(9, s.Length - 10);
                string v;
                return strings.TryGetValue(id, out v) ? v.Trim() : null;
            }
            return s;
        }
    }
}
