namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text;
    using System.Threading;
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

    // User Group Policy from Resultant Set of Policy, for one user SID. Optional, so sources that only read the computer keep working.
    public interface IUserRsopSource
    {
        List<RsopValue> UserValues(string sid, out string note);
    }

    public sealed class EventItem
    {
        public DateTime Time;
        public int Id;
        public string Level;
        public string Message;
        // The event data in template order. Used when the message is missing or has no labels.
        public string[] Properties;
    }

    public interface IEventSource
    {
        List<EventItem> Read(string channel, DateTime since, bool errorsOnly);
    }

    // A source that can say why it returned less than expected. Optional.
    public interface ISourceNote
    {
        string Note { get; }
    }

    // Runs work on a background thread and waits a limited time, so a hanging call (WMI) cannot hang the app.
    public static class Guard
    {
        public static bool Run(ThreadStart work, TimeSpan timeout, out Exception error)
        {
            Exception err = null;
            Thread t = new Thread(delegate ()
            {
                try { work(); }
                catch (Exception ex) { err = ex; }
            });
            t.IsBackground = true;
            t.Name = "PolicyVice reader";
            t.Start();
            bool done = t.Join(timeout);
            error = done ? err : null;
            return done;
        }
    }

    public sealed class LiveRegistry : IRegSource, IDisposable
    {
        readonly List<string> denied = new List<string>();
        readonly Dictionary<RegistryHive, RegistryKey> roots = new Dictionary<RegistryHive, RegistryKey>();
        readonly object gate = new object();
        string lastPath;
        RegistryKey lastKey;
        bool lastOwned;

        public List<string> Denied
        {
            get { return denied; }
        }

        RegistryKey Root(RegistryHive h)
        {
            RegistryKey k;
            if (!roots.TryGetValue(h, out k))
            {
                k = RegistryKey.OpenBaseKey(h, RegistryView.Registry64);
                roots[h] = k;
            }
            return k;
        }

        // Opens a key read-only. The last key stays open, because callers read the values of one key in a row.
        RegistryKey Key(string path)
        {
            if (lastPath != null && string.Equals(path, lastPath, StringComparison.OrdinalIgnoreCase)) return lastKey;
            if (lastKey != null && lastOwned) lastKey.Dispose();
            lastKey = null;
            lastOwned = false;
            lastPath = path;

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
                RegistryKey root = Root(h);
                if (sub.Length == 0) lastKey = root;
                else
                {
                    lastKey = root.OpenSubKey(sub, false);
                    lastOwned = lastKey != null;
                }
            }
            catch (System.Security.SecurityException) { Deny(path); }
            catch (UnauthorizedAccessException) { Deny(path); }
            catch (System.IO.IOException) { }
            catch (ArgumentException) { }
            return lastKey;
        }

        void Deny(string path)
        {
            if (!denied.Contains(path)) denied.Add(path);
        }

        public string[] SubKeys(string path)
        {
            lock (gate)
            {
                RegistryKey k = Key(path);
                if (k == null) return new string[0];
                try { return k.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { Deny(path); }
                catch (UnauthorizedAccessException) { Deny(path); }
                catch (Exception) { }
                return new string[0];
            }
        }

        public string[] ValueNames(string path)
        {
            lock (gate)
            {
                RegistryKey k = Key(path);
                if (k == null) return new string[0];
                try { return k.GetValueNames(); }
                catch (System.Security.SecurityException) { Deny(path); }
                catch (UnauthorizedAccessException) { Deny(path); }
                catch (Exception) { }
                return new string[0];
            }
        }

        public RegValue Get(string path, string name)
        {
            lock (gate)
            {
                RegistryKey k = Key(path);
                if (k == null) return null;
                try
                {
                    object v = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (v == null) return null;
                    RegistryValueKind kind = k.GetValueKind(name);
                    return new RegValue(KindName(kind), Format(v));
                }
                catch (System.Security.SecurityException) { Deny(path); }
                catch (UnauthorizedAccessException) { Deny(path); }
                catch (Exception) { }
                return null;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (lastKey != null && lastOwned) lastKey.Dispose();
                lastKey = null;
                lastPath = null;
                foreach (RegistryKey k in roots.Values) k.Dispose();
                roots.Clear();
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
            if (v is int) return unchecked((uint)(int)v).ToString(CultureInfo.InvariantCulture);
            if (v is long) return unchecked((ulong)(long)v).ToString(CultureInfo.InvariantCulture);
            string[] multi = v as string[];
            if (multi != null) return string.Join("; ", multi);
            byte[] bytes = v as byte[];
            if (bytes != null) return Hex(bytes);
            return Convert.ToString(v, CultureInfo.InvariantCulture);
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

    // Group Policy registry settings from WMI: root\RSOP\Computer, and root\RSOP\User\<SID with each - replaced by _> for a user.
    // Every query has a WMI timeout and runs on a guarded thread, so a stuck WMI service cannot hang the app.
    public sealed class LiveRsop : IRsopSource, IUserRsopSource
    {
        public TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);
        public TimeSpan TotalTimeout = TimeSpan.FromSeconds(45);
        bool stuck;

        public List<RsopValue> ComputerValues(out string note)
        {
            return Read(@"\\.\root\RSOP\Computer", false, out note);
        }

        public List<RsopValue> UserValues(string sid, out string note)
        {
            if (string.IsNullOrEmpty(sid))
            {
                note = "The user SID is not known.";
                return new List<RsopValue>();
            }
            return Read(@"\\.\root\RSOP\User\" + UserNamespace(sid), true, out note);
        }

        public static string UserNamespace(string sid)
        {
            return sid.Replace('-', '_');
        }

        List<RsopValue> Read(string ns, bool user, out string note)
        {
            note = null;
            if (stuck)
            {
                note = "Skipped, because an earlier Resultant Set of Policy query did not answer.";
                return new List<RsopValue>();
            }
            List<RsopValue> list = null;
            string inner = null;
            Exception error;
            bool done = Guard.Run(delegate { list = Query(ns, QueryTimeout, out inner); }, TotalTimeout, out error);
            if (!done)
            {
                stuck = true;
                note = "Resultant Set of Policy did not answer within " + (int)TotalTimeout.TotalSeconds + " seconds.";
                return new List<RsopValue>();
            }
            if (error != null)
            {
                note = Explain(error, ns, user);
                return new List<RsopValue>();
            }
            note = inner;
            return list ?? new List<RsopValue>();
        }

        static string Explain(Exception ex, string ns, bool user)
        {
            System.Management.ManagementException me = ex as System.Management.ManagementException;
            if (me != null)
            {
                switch (me.ErrorCode)
                {
                    case System.Management.ManagementStatus.InvalidNamespace:
                        return user
                            ? "There is no user Resultant Set of Policy for this user (" + ns.Substring(4) + " does not exist). Group Policy has not run for this user on this device."
                            : "There is no Resultant Set of Policy on this device (" + ns.Substring(4) + " does not exist).";
                    case System.Management.ManagementStatus.AccessDenied:
                        return "Resultant Set of Policy needs administrator rights.";
                    case System.Management.ManagementStatus.Timedout:
                        return "Resultant Set of Policy timed out.";
                }
                return "Resultant Set of Policy is not available: " + me.Message.Trim();
            }
            if (ex is UnauthorizedAccessException) return "Resultant Set of Policy needs administrator rights.";
            if (ex is System.Runtime.InteropServices.COMException) return "Resultant Set of Policy is not available: " + ex.Message.Trim();
            return "Resultant Set of Policy could not be read: " + ex.Message.Trim();
        }

        static System.Management.EnumerationOptions Options(TimeSpan timeout)
        {
            System.Management.EnumerationOptions o = new System.Management.EnumerationOptions();
            o.Timeout = timeout;
            o.ReturnImmediately = true;
            o.Rewindable = false;
            o.EnsureLocatable = false;
            return o;
        }

        static List<RsopValue> Query(string ns, TimeSpan timeout, out string note)
        {
            note = null;
            List<RsopValue> list = new List<RsopValue>();
            Dictionary<string, string> byId = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> byGuid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            System.Management.ConnectionOptions co = new System.Management.ConnectionOptions();
            co.Timeout = timeout;
            co.Impersonation = System.Management.ImpersonationLevel.Impersonate;
            System.Management.ManagementScope scope = new System.Management.ManagementScope(ns, co);
            scope.Connect();
            using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(scope, new System.Management.ObjectQuery("SELECT id, guidName, name FROM RSOP_GPO"), Options(timeout)))
            using (System.Management.ManagementObjectCollection c = s.Get())
            {
                foreach (System.Management.ManagementBaseObject o in c)
                {
                    string id = Convert.ToString(o["id"]);
                    string name = Convert.ToString(o["name"]);
                    if (!string.IsNullOrEmpty(id)) byId[id] = name;
                    string guid = Convert.ToString(o["guidName"]);
                    if (!string.IsNullOrEmpty(guid)) byGuid[guid.Trim('{', '}')] = name;
                }
            }
            using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(scope, new System.Management.ObjectQuery("SELECT registryKey, valueName, value, valueType, precedence, GPOID, deleted FROM RSOP_RegistryPolicySetting"), Options(timeout)))
            using (System.Management.ManagementObjectCollection c = s.Get())
            {
                foreach (System.Management.ManagementBaseObject o in c)
                {
                    RsopValue r = new RsopValue();
                    r.Key = Convert.ToString(o["registryKey"]);
                    if (string.IsNullOrEmpty(r.Key)) continue;
                    r.ValueName = Convert.ToString(o["valueName"]);
                    r.GpoId = Convert.ToString(o["GPOID"]);
                    object p = o["precedence"];
                    r.Precedence = p == null ? 0 : Convert.ToInt32(p, CultureInfo.InvariantCulture);
                    object d = o["deleted"];
                    r.Deleted = d != null && Convert.ToBoolean(d, CultureInfo.InvariantCulture);
                    object t = o["valueType"];
                    int type = t == null ? 0 : Convert.ToInt32(t, CultureInfo.InvariantCulture);
                    r.Kind = TypeName(type);
                    r.Data = Decode(o["value"] as byte[], type);
                    r.GpoName = GpoName(r.GpoId, byId, byGuid);
                    list.Add(r);
                }
            }
            return list;
        }

        // GPOID and RSOP_GPO.id hold the same string (LocalGPO, or CN={GUID},CN=Policies,CN=System,DC=...). The GUID is a fallback.
        public static string GpoName(string gpoId, Dictionary<string, string> byId, Dictionary<string, string> byGuid)
        {
            if (string.IsNullOrEmpty(gpoId)) return gpoId;
            string name;
            if (byId.TryGetValue(gpoId, out name) && !string.IsNullOrEmpty(name)) return name;
            int a = gpoId.IndexOf('{'), b = gpoId.IndexOf('}');
            if (a >= 0 && b > a && byGuid.TryGetValue(gpoId.Substring(a + 1, b - a - 1), out name) && !string.IsNullOrEmpty(name)) return name;
            return gpoId;
        }

        public static string TypeName(int t)
        {
            switch (t)
            {
                case 1: return "REG_SZ";
                case 2: return "REG_EXPAND_SZ";
                case 3: return "REG_BINARY";
                case 4: return "REG_DWORD";
                case 5: return "REG_DWORD_BIG_ENDIAN";
                case 7: return "REG_MULTI_SZ";
                case 11: return "REG_QWORD";
                default: return "REG_NONE";
            }
        }

        public static string Decode(byte[] b, int type)
        {
            if (b == null) return "";
            try
            {
                switch (type)
                {
                    case 4: return b.Length >= 4 ? BitConverter.ToUInt32(b, 0).ToString(CultureInfo.InvariantCulture) : LiveRegistry.Hex(b);
                    case 5: return b.Length >= 4 ? ((uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3])).ToString(CultureInfo.InvariantCulture) : LiveRegistry.Hex(b);
                    case 11: return b.Length >= 8 ? BitConverter.ToUInt64(b, 0).ToString(CultureInfo.InvariantCulture) : LiveRegistry.Hex(b);
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

    public sealed class LiveEvents : IEventSource, ISourceNote
    {
        public int MaxEvents = 5000;
        string note;

        public string Note
        {
            get { return note; }
        }

        public List<EventItem> Read(string channel, DateTime since, bool errorsOnly)
        {
            note = null;
            List<EventItem> list = new List<EventItem>();
            string ms = Math.Max(0, (long)(DateTime.UtcNow - since.ToUniversalTime()).TotalMilliseconds).ToString(CultureInfo.InvariantCulture);
            string level = errorsOnly ? " and (Level=1 or Level=2 or Level=3)" : "";
            string xpath = "*[System[TimeCreated[timediff(@SystemTime) <= " + ms + "]" + level + "]]";
            // FormatDescription looks up message texts in the language of the regional format, not of Windows.
            // With a Danish format on English Windows the texts are empty, so read them in the display language.
            System.Globalization.CultureInfo keep = System.Threading.Thread.CurrentThread.CurrentCulture;
            try { System.Threading.Thread.CurrentThread.CurrentCulture = CultureInfo.CreateSpecificCulture(CultureInfo.CurrentUICulture.Name); }
            catch (Exception) { }
            try
            {
                System.Diagnostics.Eventing.Reader.EventLogQuery q = new System.Diagnostics.Eventing.Reader.EventLogQuery(channel, System.Diagnostics.Eventing.Reader.PathType.LogName, xpath);
                q.ReverseDirection = true;
                using (System.Diagnostics.Eventing.Reader.EventLogReader r = new System.Diagnostics.Eventing.Reader.EventLogReader(q))
                {
                    while (true)
                    {
                        if (list.Count >= MaxEvents)
                        {
                            note = "Only the newest " + MaxEvents + " events were read.";
                            break;
                        }
                        System.Diagnostics.Eventing.Reader.EventRecord e;
                        try { e = r.ReadEvent(); }
                        catch (System.Diagnostics.Eventing.Reader.EventLogException ex)
                        {
                            note = "Reading stopped after " + list.Count + " events: " + ex.Message.Trim();
                            break;
                        }
                        if (e == null) break;
                        using (e)
                        {
                            EventItem it = ToItem(e);
                            if (it != null) list.Add(it);
                        }
                    }
                }
            }
            catch (System.Diagnostics.Eventing.Reader.EventLogNotFoundException) { note = "The event log " + channel + " does not exist on this device."; }
            catch (UnauthorizedAccessException) { note = "The event log " + channel + " could not be opened: access denied."; }
            catch (Exception ex) { note = "The event log " + channel + " could not be read: " + ex.Message.Trim(); }
            finally { System.Threading.Thread.CurrentThread.CurrentCulture = keep; }
            return list;
        }

        static EventItem ToItem(System.Diagnostics.Eventing.Reader.EventRecord e)
        {
            try
            {
                EventItem it = new EventItem();
                it.Time = e.TimeCreated.HasValue ? e.TimeCreated.Value : DateTime.MinValue;
                it.Id = e.Id;
                byte lv = e.Level.HasValue ? e.Level.Value : (byte)4;
                it.Level = lv == 1 || lv == 2 ? "Error" : lv == 3 ? "Warning" : "Information";
                List<string> props = new List<string>();
                try
                {
                    foreach (System.Diagnostics.Eventing.Reader.EventProperty p in e.Properties) props.Add(PropertyText(p.Value));
                }
                catch (Exception) { }
                it.Properties = props.ToArray();
                try { it.Message = e.FormatDescription(); } catch (Exception) { it.Message = null; }
                if (string.IsNullOrEmpty(it.Message)) it.Message = string.Join(", ", it.Properties);
                return it;
            }
            catch (Exception) { return null; }
        }

        // 32-bit numbers are shown as hex, the way the MDM events print HRESULTs.
        public static string PropertyText(object v)
        {
            if (v == null) return "";
            if (v is uint) return "0x" + ((uint)v).ToString("X8", CultureInfo.InvariantCulture);
            if (v is int) return "0x" + unchecked((uint)(int)v).ToString("X8", CultureInfo.InvariantCulture);
            if (v is Guid) return ((Guid)v).ToString("D").ToUpperInvariant();
            if (v is DateTime) return ((DateTime)v).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            byte[] bytes = v as byte[];
            if (bytes != null) return LiveRegistry.Hex(bytes);
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }
    }
}
