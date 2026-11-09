namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Threading;
    using Microsoft.Win32;

    public sealed class Change
    {
        public string Kind;
        public DateTime Time;
        public string Layer;
        public string Scope;
        public string Area;
        public string Name;
        public string FriendlyName;
        public string OldValue;
        public string NewValue;
        public string OldSource;
        public string NewSource;
        public string RegistryPath;
        public List<MdmError> Events = new List<MdmError>();

        public string Setting
        {
            get { return string.IsNullOrEmpty(FriendlyName) ? Name : FriendlyName; }
        }
    }

    public static class Differ
    {
        public const string Added = "Added";
        public const string Removed = "Removed";
        public const string Changed = "Changed";

        public const string SourceChanged = "Source changed";

        public static List<Change> Compare(Snapshot before, Snapshot after)
        {
            return Compare(before, after, true);
        }

        // sources: also list settings whose value stayed the same but whose source changed. The watch log leaves them
        // out, because a Group Policy refresh can briefly make Resultant Set of Policy unavailable.
        public static List<Change> Compare(Snapshot before, Snapshot after, bool sources)
        {
            List<Change> list = new List<Change>();
            Dictionary<string, PolicySetting> a = Index(before);
            Dictionary<string, PolicySetting> b = Index(after);
            DateTime when = after.TakenUtc.ToLocalTime();
            foreach (KeyValuePair<string, PolicySetting> kv in a)
            {
                PolicySetting n;
                if (!b.TryGetValue(kv.Key, out n))
                {
                    list.Add(Make(Removed, when, kv.Value, kv.Value.Value, null, kv.Value.Source, null));
                    continue;
                }
                PolicySetting o = kv.Value;
                if (o.Value != n.Value) list.Add(Make(Changed, when, n, o.Value, n.Value, o.Source, n.Source));
                else if (sources && o.Source != n.Source) list.Add(Make(SourceChanged, when, n, o.Value, n.Value, o.Source, n.Source));
            }
            foreach (KeyValuePair<string, PolicySetting> kv in b)
                if (!a.ContainsKey(kv.Key))
                    list.Add(Make(Added, when, kv.Value, null, kv.Value.Value, null, kv.Value.Source));
            list.Sort(delegate (Change x, Change y)
            {
                int c = string.CompareOrdinal(x.Layer, y.Layer);
                if (c != 0) return c;
                c = string.Compare(x.Area, y.Area, StringComparison.OrdinalIgnoreCase);
                return c != 0 ? c : string.Compare(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);
            });
            return list;
        }

        // Attaches MDM events within the given window of each change.
        public static void AttachEvents(List<Change> changes, List<MdmError> events, TimeSpan window)
        {
            foreach (Change c in changes)
                foreach (MdmError e in events)
                    if (Math.Abs((e.Time - c.Time).TotalSeconds) <= window.TotalSeconds) c.Events.Add(e);
        }

        static Dictionary<string, PolicySetting> Index(Snapshot s)
        {
            Dictionary<string, PolicySetting> d = new Dictionary<string, PolicySetting>(StringComparer.OrdinalIgnoreCase);
            foreach (PolicySetting p in s.Settings) d[p.Key] = p;
            return d;
        }

        static Change Make(string kind, DateTime when, PolicySetting p, string ov, string nv, string os, string ns)
        {
            Change c = new Change();
            c.Kind = kind;
            c.Time = when;
            c.Layer = p.Layer;
            c.Scope = p.Scope;
            c.Area = p.Area;
            c.Name = p.Name;
            c.FriendlyName = p.FriendlyName;
            c.OldValue = ov;
            c.NewValue = nv;
            c.OldSource = os;
            c.NewSource = ns;
            c.RegistryPath = p.RegistryPath;
            return c;
        }
    }

    // Raises Changed after policy registry keys change. Waits for a quiet period so a burst of writes gives one event.
    public sealed class PolicyWatcher : IDisposable
    {
        const int RegNotifyChangeName = 0x1;
        const int RegNotifyChangeLastSet = 0x4;

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int RegNotifyChangeKeyValue(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, bool bWatchSubtree, int dwNotifyFilter, Microsoft.Win32.SafeHandles.SafeWaitHandle hEvent, bool fAsynchronous);

        public static readonly string[] Paths =
        {
            @"HKLM\SOFTWARE\Microsoft\PolicyManager\current",
            @"HKLM\SOFTWARE\Policies",
            @"HKCU\SOFTWARE\Policies",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
        };

        public event EventHandler Changed;
        public TimeSpan Quiet = TimeSpan.FromSeconds(2);

        readonly ManualResetEvent stop = new ManualResetEvent(false);
        Thread thread;

        public void Start()
        {
            if (thread != null) return;
            stop.Reset();
            thread = new Thread(Run);
            thread.IsBackground = true;
            thread.Name = "PolicyVice watcher";
            thread.Start();
        }

        public void Stop()
        {
            stop.Set();
            if (thread != null && !thread.Join(3000)) { }
            thread = null;
        }

        void Run()
        {
            List<RegistryKey> keys = new List<RegistryKey>();
            List<AutoResetEvent> events = new List<AutoResetEvent>();
            try
            {
                foreach (string p in Paths)
                {
                    RegistryKey k = Open(p);
                    if (k == null) continue;
                    AutoResetEvent ev = new AutoResetEvent(false);
                    if (RegNotifyChangeKeyValue(k.Handle, true, RegNotifyChangeName | RegNotifyChangeLastSet, ev.SafeWaitHandle, true) != 0)
                    {
                        k.Dispose();
                        ev.Dispose();
                        continue;
                    }
                    keys.Add(k);
                    events.Add(ev);
                }
                if (keys.Count == 0) return;
                WaitHandle[] handles = new WaitHandle[events.Count + 1];
                handles[0] = stop;
                for (int i = 0; i < events.Count; i++) handles[i + 1] = events[i];
                while (true)
                {
                    int hit = WaitHandle.WaitAny(handles);
                    if (hit == 0) return;
                    Rearm(keys[hit - 1], events[hit - 1]);
                    while (true)
                    {
                        int more = WaitHandle.WaitAny(handles, Quiet);
                        if (more == 0) return;
                        if (more == WaitHandle.WaitTimeout) break;
                        Rearm(keys[more - 1], events[more - 1]);
                    }
                    EventHandler h = Changed;
                    if (h != null) h(this, EventArgs.Empty);
                }
            }
            catch (Exception) { }
            finally
            {
                foreach (RegistryKey k in keys) k.Dispose();
                foreach (AutoResetEvent e in events) e.Dispose();
            }
        }

        static void Rearm(RegistryKey k, AutoResetEvent ev)
        {
            RegNotifyChangeKeyValue(k.Handle, true, RegNotifyChangeName | RegNotifyChangeLastSet, ev.SafeWaitHandle, true);
        }

        static RegistryKey Open(string path)
        {
            int i = path.IndexOf('\\');
            RegistryHive h = path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            try
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(h, RegistryView.Registry64))
                {
                    return root.OpenSubKey(path.Substring(i + 1), false);
                }
            }
            catch (Exception) { return null; }
        }

        public void Dispose()
        {
            Stop();
            stop.Dispose();
        }
    }
}
