namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    // One Policy CSP setting from Microsoft's documentation: its friendly name, allowed values and Group Policy counterpart.
    public sealed class CspEntry
    {
        public string Area;
        public string Name;
        public string FriendlyName;
        public string Description;
        public string Scope;
        public string AdmxFile;
        public string AdmxPolicy;
        public string GpKey;
        public string GpValueName;
        public Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class CspCatalog
    {
        readonly Dictionary<string, CspEntry> entries = new Dictionary<string, CspEntry>(StringComparer.OrdinalIgnoreCase);

        public int Count
        {
            get { return entries.Count; }
        }

        public static CspCatalog Embedded()
        {
            return new CspCatalog();
        }

        public static CspCatalog Load(Stream stream)
        {
            return new CspCatalog();
        }

        public CspEntry Find(string area, string name)
        {
            CspEntry e;
            return area != null && name != null && entries.TryGetValue(area + "/" + name, out e) ? e : null;
        }

        // The value with its meaning, such as "1 (Allowed)", or the value as is when the meaning is not known.
        public static string Describe(CspEntry e, string value)
        {
            string m;
            if (e != null && value != null && e.Values.TryGetValue(value, out m) && !string.IsNullOrEmpty(m)) return value + " (" + m + ")";
            return value;
        }
    }
}
