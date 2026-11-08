namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using Microsoft.Win32;

    public sealed class RegValue
    {
        public string Kind;
        public string Data;

        public RegValue(string kind, string data)
        {
            Kind = kind;
            Data = data;
        }
    }

    // Read-only view of the registry. Paths start with HKLM, HKCU or HKU.
    public interface IRegSource
    {
        string[] SubKeys(string path);
        string[] ValueNames(string path);
        RegValue Get(string path, string name);
        List<string> Denied { get; }
    }

    public sealed class RsopValue
    {
        public string Key;
        public string ValueName;
        public string Data;
        public string Kind;
        public string GpoId;
        public string GpoName;
        public int Precedence;
        public bool Deleted;
    }

    public interface IRsopSource
    {
        List<RsopValue> ComputerValues(out string note);
    }

    public sealed class EventItem
    {
        public DateTime Time;
        public int Id;
        public string Level;
        public string Message;
    }

    public interface IEventSource
    {
        List<EventItem> Read(string channel, DateTime since, bool errorsOnly);
    }

    public sealed class LiveRegistry : IRegSource
    {
        readonly List<string> denied = new List<string>();

        public List<string> Denied
        {
            get { return denied; }
        }

        RegistryKey Open(string path)
        {
            int i = path.IndexOf('\\');
            string hive = i < 0 ? path : path.Substring(0, i);
            string sub = i < 0 ? "" : path.Substring(i + 1);
            RegistryHive h;
            switch (hive.ToUpperInvariant())
            {
                case "HKLM": h = RegistryHive.LocalMachine; break;
                case "HKCU": h = RegistryHive.CurrentUser; break;
                case "HKU": h = RegistryHive.Users; break;
                default: return null;
            }
            try
            {
                RegistryKey root = RegistryKey.OpenBaseKey(h, RegistryView.Registry64);
                if (sub.Length == 0) return root;
                RegistryKey k = root.OpenSubKey(sub, false);
                root.Dispose();
                return k;
            }
            catch (System.Security.SecurityException) { Deny(path); }
            catch (UnauthorizedAccessException) { Deny(path); }
            catch (System.IO.IOException) { }
            return null;
        }

        void Deny(string path)
        {
            lock (denied)
            {
                if (!denied.Contains(path)) denied.Add(path);
            }
        }

        public string[] SubKeys(string path)
        {
            using (RegistryKey k = Open(path))
            {
                if (k == null) return new string[0];
                try { return k.GetSubKeyNames(); }
                catch (Exception) { Deny(path); return new string[0]; }
            }
        }

        public string[] ValueNames(string path)
        {
            using (RegistryKey k = Open(path))
            {
                if (k == null) return new string[0];
                try { return k.GetValueNames(); }
                catch (Exception) { Deny(path); return new string[0]; }
            }
        }

        public RegValue Get(string path, string name)
        {
            using (RegistryKey k = Open(path))
            {
                if (k == null) return null;
                try
                {
                    object v = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (v == null) return null;
                    RegistryValueKind kind = k.GetValueKind(name);
                    return new RegValue(KindName(kind), Format(v));
                }
                catch (Exception) { Deny(path); return null; }
            }
        }

        static string KindName(RegistryValueKind k)
        {
            switch (k)
            {
                case RegistryValueKind.DWord: return "REG_DWORD";
                case RegistryValueKind.QWord: return "REG_QWORD";
                case RegistryValueKind.String: return "REG_SZ";
                case RegistryValueKind.ExpandString: return "REG_EXPAND_SZ";
                case RegistryValueKind.MultiString: return "REG_MULTI_SZ";
                case RegistryValueKind.Binary: return "REG_BINARY";
                default: return "REG_NONE";
            }
        }

        public static string Format(object v)
        {
            if (v is int) return unchecked((uint)(int)v).ToString();
            if (v is long) return unchecked((ulong)(long)v).ToString();
            string[] multi = v as string[];
            if (multi != null) return string.Join("; ", multi);
            byte[] bytes = v as byte[];
            if (bytes != null) return Hex(bytes);
            return Convert.ToString(v);
        }

        public static string Hex(byte[] bytes)
        {
            StringBuilder b = new StringBuilder(bytes.Length * 3);
            int max = Math.Min(bytes.Length, 256);
            for (int i = 0; i < max; i++)
            {
                if (i > 0) b.Append(' ');
                b.Append(bytes[i].ToString("X2"));
            }
            if (bytes.Length > max) b.Append(" \u2026 (" + bytes.Length + " bytes)");
            return b.ToString();
        }
    }

    public sealed class LiveRsop : IRsopSource
    {
        public List<RsopValue> ComputerValues(out string note)
        {
            note = null;
            List<RsopValue> list = new List<RsopValue>();
            Dictionary<string, string> gpoNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                System.Management.ManagementScope scope = new System.Management.ManagementScope(@"\\.\root\RSOP\Computer");
                scope.Connect();
                using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(scope, new System.Management.ObjectQuery("SELECT id, name FROM RSOP_GPO")))
                {
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        string id = Convert.ToString(o["id"]);
                        if (!string.IsNullOrEmpty(id)) gpoNames[id] = Convert.ToString(o["name"]);
                    }
                }
                using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(scope, new System.Management.ObjectQuery("SELECT registryKey, valueName, value, valueType, precedence, GPOID, deleted FROM RSOP_RegistryPolicySetting")))
                {
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        RsopValue r = new RsopValue();
                        r.Key = Convert.ToString(o["registryKey"]);
                        r.ValueName = Convert.ToString(o["valueName"]);
                        r.GpoId = Convert.ToString(o["GPOID"]);
                        object p = o["precedence"];
                        r.Precedence = p == null ? 0 : Convert.ToInt32(p);
                        object d = o["deleted"];
                        r.Deleted = d != null && Convert.ToBoolean(d);
                        object t = o["valueType"];
                        int type = t == null ? 0 : Convert.ToInt32(t);
                        r.Kind = TypeName(type);
                        r.Data = Decode(o["value"] as byte[], type);
                        string name;
                        r.GpoName = r.GpoId != null && gpoNames.TryGetValue(r.GpoId, out name) ? name : r.GpoId;
                        if (string.IsNullOrEmpty(r.Key)) continue;
                        list.Add(r);
                    }
                }
            }
            catch (UnauthorizedAccessException) { note = "Resultant Set of Policy needs administrator rights."; }
            catch (System.Management.ManagementException ex) { note = "Resultant Set of Policy is not available: " + ex.Message.Trim(); }
            catch (System.Runtime.InteropServices.COMException ex) { note = "Resultant Set of Policy is not available: " + ex.Message.Trim(); }
            catch (Exception ex) { note = "Resultant Set of Policy could not be read: " + ex.Message.Trim(); }
            return list;
        }

        static string TypeName(int t)
        {
            switch (t)
            {
                case 1: return "REG_SZ";
                case 2: return "REG_EXPAND_SZ";
                case 3: return "REG_BINARY";
                case 4: return "REG_DWORD";
                case 7: return "REG_MULTI_SZ";
                case 11: return "REG_QWORD";
                default: return "REG_NONE";
            }
        }

        static string Decode(byte[] b, int type)
        {
            if (b == null) return "";
            try
            {
                switch (type)
                {
                    case 4: return b.Length >= 4 ? BitConverter.ToUInt32(b, 0).ToString() : "";
                    case 11: return b.Length >= 8 ? BitConverter.ToUInt64(b, 0).ToString() : "";
                    case 1:
                    case 2:
                        return Encoding.Unicode.GetString(b).TrimEnd('\0');
                    case 7:
                        return string.Join("; ", Encoding.Unicode.GetString(b).TrimEnd('\0').Split('\0'));
                    default: return LiveRegistry.Hex(b);
                }
            }
            catch (Exception) { return LiveRegistry.Hex(b); }
        }
    }

    public sealed class LiveEvents : IEventSource
    {
        public List<EventItem> Read(string channel, DateTime since, bool errorsOnly)
        {
            List<EventItem> list = new List<EventItem>();
            string ms = Math.Max(0, (long)(DateTime.UtcNow - since.ToUniversalTime()).TotalMilliseconds).ToString();
            string level = errorsOnly ? " and (Level=1 or Level=2 or Level=3)" : "";
            string xpath = "*[System[TimeCreated[timediff(@SystemTime) <= " + ms + "]" + level + "]]";
            try
            {
                System.Diagnostics.Eventing.Reader.EventLogQuery q = new System.Diagnostics.Eventing.Reader.EventLogQuery(channel, System.Diagnostics.Eventing.Reader.PathType.LogName, xpath);
                q.ReverseDirection = true;
                using (System.Diagnostics.Eventing.Reader.EventLogReader r = new System.Diagnostics.Eventing.Reader.EventLogReader(q))
                {
                    for (int n = 0; n < 5000; n++)
                    {
                        System.Diagnostics.Eventing.Reader.EventRecord e = r.ReadEvent();
                        if (e == null) break;
                        using (e)
                        {
                            EventItem it = new EventItem();
                            it.Time = e.TimeCreated.HasValue ? e.TimeCreated.Value : DateTime.MinValue;
                            it.Id = e.Id;
                            byte lv = e.Level.HasValue ? e.Level.Value : (byte)4;
                            it.Level = lv <= 2 ? "Error" : lv == 3 ? "Warning" : "Information";
                            try { it.Message = e.FormatDescription(); } catch (Exception) { it.Message = null; }
                            if (string.IsNullOrEmpty(it.Message))
                            {
                                StringBuilder b = new StringBuilder();
                                try
                                {
                                    foreach (System.Diagnostics.Eventing.Reader.EventProperty p in e.Properties)
                                    {
                                        if (b.Length > 0) b.Append(", ");
                                        b.Append(Convert.ToString(p.Value));
                                    }
                                }
                                catch (Exception) { }
                                it.Message = b.ToString();
                            }
                            list.Add(it);
                        }
                    }
                }
            }
            catch (Exception) { }
            return list;
        }
    }
}
