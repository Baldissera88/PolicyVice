namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text.RegularExpressions;
    using System.Threading;

    public sealed class CollectOptions
    {
        public int EventDays = 7;
        public string CurrentUserSid;
        public string Computer;
        public string UserName;
        public string OsVersion;
        public bool Elevated;
        public string Version;
        public DateTime NowUtc = DateTime.UtcNow;
    }

    public static class Collector
    {
        public const string PolicyManager = @"HKLM\SOFTWARE\Microsoft\PolicyManager";
        public const string Enrollments = @"HKLM\SOFTWARE\Microsoft\Enrollments";
        public const string MdmChannel = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";
        public const int MaxRegistryValues = 20000;

        // Companion values next to each setting in PolicyManager (see docs/research/sources.md).
        static readonly string[] Suffixes = { "_ProviderSet", "_WinningProvider", "_LastWrite", "_ADMXInstanceData" };
        static readonly Regex RxUri = new Regex(@"CSP URI:\s*\(([^)]*)\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxUriLoose = new Regex(@"\./(?:Device/|User/)?Vendor/MSFT/[^\s,)""]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxResult = new Regex(@"Result:\s*\(([^)]*)\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxHex = new Regex(@"0x[0-9A-Fa-f]{8}", RegexOptions.Compiled);
        static readonly Regex RxField = new Regex(@"([A-Za-z][A-Za-z ]*?)\s*:\s*\(([^()]*)\)", RegexOptions.Compiled);
        static readonly Regex RxHresult = new Regex(@"^0x[89A-Fa-f][0-9A-Fa-f]{7}$", RegexOptions.Compiled);
        static readonly Regex RxSid = new Regex(@"^S-1-\d+(-\d+)+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Policy CSP areas that have a Group Policy counterpart outside ADMX-backed policies.
        static readonly string[,] Overlaps =
        {
            { "Update", @"Microsoft\Windows\WindowsUpdate" },
            { "Defender", @"Microsoft\Windows Defender" },
            { "DeliveryOptimization", @"Microsoft\Windows\DeliveryOptimization" },
            { "Power", @"Microsoft\Power\PowerSettings" },
            { "WindowsLogon", @"Microsoft\Windows\System" },
            { "Experience", @"Microsoft\Windows\CloudContent" },
        };

        public static Snapshot Collect(IRegSource reg, IRsopSource rsop, IEventSource events, AdmxCatalog catalog, CollectOptions opt)
        {
            if (reg == null) throw new ArgumentNullException("reg");
            if (catalog == null) catalog = new AdmxCatalog();
            if (opt == null) opt = new CollectOptions();
            Snapshot s = new Snapshot();
            s.ToolVersion = opt.Version;
            s.Computer = opt.Computer;
            s.UserName = opt.UserName;
            s.OsVersion = opt.OsVersion;
            s.Elevated = opt.Elevated;
            s.TakenUtc = opt.NowUtc;
            s.EventDays = opt.EventDays;

            // Each source runs on its own. A source that fails becomes a note.
            Step(s, "Enrollments", delegate { ReadEnrollments(reg, s); });
            Step(s, "Device information", delegate { s.Device = DeviceCollector.Collect(reg) ?? new DeviceInfo(); });
            Step(s, "Intune Management Extension", delegate { s.Intune = ImeCollector.Collect(reg) ?? new List<ImeItem>(); });
            Step(s, "Ingested ADMX", delegate { ReadAdmxInstalled(reg, s, catalog); });
            Step(s, "MDM policy", delegate { ReadMdm(reg, s, catalog); });
            Step(s, "MDMWinsOverGP", delegate
            {
                RegValue wins = reg.Get(PolicyManager + @"\current\device\ControlPolicyConflict", "MDMWinsOverGP");
                s.MdmWinsOverGp = wins != null && wins.Data == "1";
            });

            List<RsopValue> gp = new List<RsopValue>();
            if (rsop == null) s.RsopNote = "Resultant Set of Policy was not read.";
            else
            {
                string note = null;
                try { gp = rsop.ComputerValues(out note) ?? new List<RsopValue>(); }
                catch (Exception ex)
                {
                    gp = new List<RsopValue>();
                    note = "Resultant Set of Policy could not be read: " + ex.Message.Trim();
                }
                s.RsopAvailable = note == null;
                s.RsopNote = note;
            }
            Step(s, "Policy registry", delegate { ReadPolicyRegistry(reg, s, catalog, gp, rsop as IUserRsopSource, opt); });
            if (events != null && opt.EventDays > 0) Step(s, "MDM events", delegate { ReadErrors(events, s, opt); });
            Step(s, "Findings", delegate { Correlate(reg, s, catalog); });
            Step(s, "Access denied list", delegate
            {
                foreach (string d in reg.Denied) if (!s.AccessDenied.Contains(d)) s.AccessDenied.Add(d);
            });
            Step(s, "Sorting", delegate
            {
                s.Settings.Sort(delegate (PolicySetting a, PolicySetting b)
                {
                    int c = string.CompareOrdinal(a.Layer, b.Layer);
                    if (c != 0) return c;
                    c = string.Compare(a.Area, b.Area, StringComparison.OrdinalIgnoreCase);
                    return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                });
            });
            if (s.Device == null) s.Device = new DeviceInfo();
            foreach (string n in s.Notes) s.Device.Add("Collection", "Note", n);
            return s;
        }

        static void Step(Snapshot s, string what, ThreadStart work)
        {
            try { work(); }
            catch (Exception ex) { Note(s, what + " could not be read: " + ex.Message.Trim()); }
        }

        static void Note(Snapshot s, string text)
        {
            if (!s.Notes.Contains(text)) s.Notes.Add(text);
        }

        static void ReadEnrollments(IRegSource reg, Snapshot s)
        {
            // Subkeys such as Context or Status have no ProviderID and are not enrollments.
            foreach (string id in reg.SubKeys(Enrollments))
            {
                string p = Enrollments + "\\" + id;
                RegValue provider = reg.Get(p, "ProviderID");
                if (provider == null || string.IsNullOrEmpty(provider.Data)) continue;
                Enrollment e = new Enrollment();
                e.Id = id;
                e.ProviderId = provider.Data;
                e.Upn = Str(reg.Get(p, "UPN"));
                e.EnrollmentType = Int(reg.Get(p, "EnrollmentType"));
                e.EnrollmentState = Int(reg.Get(p, "EnrollmentState"));
                e.DiscoveryUrl = Str(reg.Get(p, "DiscoveryServiceFullURL"));
                s.Enrollments.Add(e);
            }
        }

        static void ReadAdmxInstalled(IRegSource reg, Snapshot s, AdmxCatalog catalog)
        {
            // AdmxInstalled\<provider>\<app>\<Policy|Preference>\<file id>
            string root = PolicyManager + @"\AdmxInstalled";
            foreach (string provider in reg.SubKeys(root))
            {
                foreach (string app in reg.SubKeys(root + "\\" + provider))
                {
                    foreach (string type in reg.SubKeys(root + "\\" + provider + "\\" + app))
                    {
                        string tp = root + "\\" + provider + "\\" + app + "\\" + type;
                        List<string> ids = new List<string>(reg.SubKeys(tp));
                        foreach (string v in reg.ValueNames(tp)) if (v.Length > 0 && !ids.Contains(v)) ids.Add(v);
                        foreach (string id in ids)
                        {
                            AdmxFile f = new AdmxFile();
                            f.ProviderId = provider;
                            f.App = app;
                            f.SettingType = type;
                            f.Id = id;
                            f.Origin = "Registry";
                            RegValue text = reg.Get(tp, id);
                            if (text != null && text.Data != null && text.Data.IndexOf("<policyDefinitions", StringComparison.OrdinalIgnoreCase) >= 0)
                                f.Policies = catalog.Load(app + "_" + id, text.Data, null, true);
                            s.AdmxFiles.Add(f);
                        }
                    }
                }
            }
        }

        static void ReadMdm(IRegSource reg, Snapshot s, AdmxCatalog catalog)
        {
            string current = PolicyManager + @"\current";
            Dictionary<string, PolicySetting> map = new Dictionary<string, PolicySetting>(StringComparer.OrdinalIgnoreCase);
            foreach (string scopeKey in reg.SubKeys(current))
            {
                bool device = string.Equals(scopeKey, "device", StringComparison.OrdinalIgnoreCase);
                if (!device && !RxSid.IsMatch(scopeKey)) continue;
                foreach (string area in reg.SubKeys(current + "\\" + scopeKey))
                {
                    string ap = current + "\\" + scopeKey + "\\" + area;
                    foreach (string name in reg.ValueNames(ap))
                    {
                        if (name.Length == 0 || IsSuffix(name)) continue;
                        RegValue v = reg.Get(ap, name);
                        if (v == null) continue;
                        PolicySetting p = new PolicySetting();
                        p.Layer = Layers.Mdm;
                        p.Scope = device ? "Device" : "User";
                        p.UserSid = device ? null : scopeKey;
                        p.Area = area;
                        p.Name = name;
                        p.Value = v.Data;
                        p.ValueKind = v.Kind;
                        p.RegistryPath = ap;
                        p.CspUri = (device ? "./Device" : "./User") + "/Vendor/MSFT/Policy/Config/" + area + "/" + name;
                        RegValue win = reg.Get(ap, name + "_WinningProvider");
                        p.WinningProvider = win != null && !string.IsNullOrEmpty(win.Data) ? win.Data : null;
                        AdmxPolicy a = catalog.ForMdm(area, name);
                        if (a != null)
                        {
                            p.FriendlyName = a.DisplayName;
                            p.Description = a.Explain;
                        }
                        if (string.IsNullOrEmpty(p.FriendlyName)) p.FriendlyName = Txt.SplitCamel(name);
                        map[ScopeKey(p.Scope, p.UserSid, area, name)] = p;
                        s.Settings.Add(p);
                    }
                }
            }

            string providers = PolicyManager + @"\providers";
            int deniedBefore = reg.Denied.Count;
            foreach (string provider in reg.SubKeys(providers))
            {
                string def = providers + "\\" + provider + "\\default";
                foreach (string scopeKey in reg.SubKeys(def))
                {
                    bool device = string.Equals(scopeKey, "Device", StringComparison.OrdinalIgnoreCase);
                    if (!device && !RxSid.IsMatch(scopeKey)) continue;
                    foreach (string area in reg.SubKeys(def + "\\" + scopeKey))
                    {
                        string ap = def + "\\" + scopeKey + "\\" + area;
                        foreach (string name in reg.ValueNames(ap))
                        {
                            if (name.Length == 0 || IsSuffix(name)) continue;
                            PolicySetting p;
                            if (!map.TryGetValue(ScopeKey(device ? "Device" : "User", device ? null : scopeKey, area, name), out p)) continue;
                            RegValue v = reg.Get(ap, name);
                            Contribution c = new Contribution();
                            Enrollment e = s.FindEnrollment(provider);
                            if (e == null)
                            {
                                c.Source = Sources.Unknown;
                                c.Detail = "provider " + provider + ", not an MDM enrollment on this device";
                            }
                            else
                            {
                                c.Source = e.IsIntune ? Sources.Intune : Sources.OtherMdm;
                                c.Detail = (e.IsIntune ? "" : e.ProviderId + ", ") + (string.IsNullOrEmpty(e.Upn) ? "" : e.Upn + ", ") + "enrollment " + provider;
                            }
                            c.ProviderId = provider;
                            c.Value = v == null ? "" : v.Data;
                            c.RegistryPath = ap;
                            c.Wins = SameGuid(provider, p.WinningProvider);
                            p.Contributions.Add(c);
                        }
                    }
                }
            }
            bool providersComplete = true;
            for (int i = deniedBefore; i < reg.Denied.Count; i++)
                if (reg.Denied[i].StartsWith(providers, StringComparison.OrdinalIgnoreCase)) providersComplete = false;
            if (!providersComplete) Note(s, "Some keys under PolicyManager\\providers could not be read, so orphaned MDM values are not reported. Run as administrator.");

            foreach (PolicySetting p in s.Settings)
            {
                if (p.Layer != Layers.Mdm) continue;
                string winner = p.WinningProvider;
                if (string.IsNullOrEmpty(winner) && p.Contributions.Count == 1)
                {
                    winner = p.Contributions[0].ProviderId;
                    p.Contributions[0].Wins = true;
                }
                Enrollment e = s.FindEnrollment(winner);
                if (e != null)
                {
                    p.Source = e.IsIntune ? Sources.Intune : Sources.OtherMdm;
                    p.SourceDetail = string.IsNullOrEmpty(e.Upn) ? (e.IsIntune ? e.Id : e.ProviderId) : e.Upn;
                }
                else if (!string.IsNullOrEmpty(winner))
                {
                    // A provider GUID that is not an enrollment. PolicyManager has providers that are not MDM servers.
                    p.Source = Sources.Unknown;
                    p.SourceDetail = "Provider " + winner + " (not an MDM enrollment on this device)";
                }
                else
                {
                    p.Source = Sources.Unknown;
                    p.SourceDetail = p.Contributions.Count > 1 ? "Several providers set it and no winning provider is recorded" : null;
                }
                if (p.Contributions.Count == 0 && providersComplete)
                    p.Add(FindingKinds.Orphan, "Set in PolicyManager\\current, but no provider under PolicyManager\\providers sets it. A removed profile or enrollment may have left it behind.");
            }
        }

        // One policy root: HKLM, HKCU or HKU\<SID> \SOFTWARE\Policies, with the Group Policy values that apply to it.
        sealed class PolicyRoot
        {
            public string Path;
            public string Scope;
            public string Sid;
            public string Hive;
            public bool RsopRead;
            public bool RsopOk;
            public string RsopNote;
            public Dictionary<string, List<RsopValue>> Gpo;
        }

        static Dictionary<string, List<RsopValue>> IndexRsop(List<RsopValue> gp)
        {
            Dictionary<string, List<RsopValue>> d = new Dictionary<string, List<RsopValue>>(StringComparer.OrdinalIgnoreCase);
            if (gp == null) return d;
            foreach (RsopValue r in gp)
            {
                if (r == null || r.Deleted || string.IsNullOrEmpty(r.Key)) continue;
                // Registry.pol directives such as **del. are not values.
                if (r.ValueName != null && r.ValueName.StartsWith("**", StringComparison.Ordinal)) continue;
                string k = r.Key.Trim('\\') + "|" + (r.ValueName ?? "");
                List<RsopValue> l;
                if (!d.TryGetValue(k, out l)) { l = new List<RsopValue>(); d[k] = l; }
                l.Add(r);
            }
            foreach (List<RsopValue> l in d.Values)
                l.Sort(delegate (RsopValue x, RsopValue y) { return x.Precedence.CompareTo(y.Precedence); });
            return d;
        }

        static void ReadUserRsop(PolicyRoot root, IUserRsopSource users, Snapshot s)
        {
            root.RsopRead = true;
            root.Gpo = new Dictionary<string, List<RsopValue>>(StringComparer.OrdinalIgnoreCase);
            if (users == null) { root.RsopNote = "User Group Policy was not read"; return; }
            if (string.IsNullOrEmpty(root.Sid)) { root.RsopNote = "The user SID is not known"; return; }
            string note = null;
            List<RsopValue> list;
            try { list = users.UserValues(root.Sid, out note); }
            catch (Exception ex)
            {
                list = null;
                note = "User Group Policy could not be read: " + ex.Message.Trim();
            }
            root.RsopOk = note == null && list != null;
            root.RsopNote = note;
            if (root.RsopOk) root.Gpo = IndexRsop(list);
            else Note(s, "User Group Policy for " + root.Sid + ": " + (note ?? "not available"));
        }

        static void ReadPolicyRegistry(IRegSource reg, Snapshot s, AdmxCatalog catalog, List<RsopValue> gp, IUserRsopSource users, CollectOptions opt)
        {
            Dictionary<AdmxPolicy, List<PolicySetting>> mdmByAdmx = new Dictionary<AdmxPolicy, List<PolicySetting>>();
            foreach (PolicySetting p in s.Settings)
            {
                if (p.Layer != Layers.Mdm) continue;
                AdmxPolicy a = catalog.ForMdm(p.Area, p.Name);
                if (a == null) continue;
                List<PolicySetting> l;
                if (!mdmByAdmx.TryGetValue(a, out l)) { l = new List<PolicySetting>(); mdmByAdmx[a] = l; }
                l.Add(p);
            }

            List<PolicyRoot> roots = new List<PolicyRoot>();
            PolicyRoot machine = new PolicyRoot();
            machine.Path = @"HKLM\SOFTWARE\Policies";
            machine.Scope = "Device";
            machine.Hive = "HKLM";
            machine.RsopRead = true;
            machine.RsopOk = s.RsopAvailable;
            machine.RsopNote = s.RsopNote;
            machine.Gpo = IndexRsop(gp);
            roots.Add(machine);
            PolicyRoot hkcu = new PolicyRoot();
            hkcu.Path = @"HKCU\SOFTWARE\Policies";
            hkcu.Scope = "User";
            hkcu.Sid = opt.CurrentUserSid;
            hkcu.Hive = "HKCU";
            roots.Add(hkcu);
            List<string> sids = new List<string>();
            foreach (PolicySetting p in s.Settings) if (p.UserSid != null && !sids.Contains(p.UserSid)) sids.Add(p.UserSid);
            foreach (string sid in sids)
            {
                if (string.Equals(sid, opt.CurrentUserSid, StringComparison.OrdinalIgnoreCase)) continue;
                PolicyRoot u = new PolicyRoot();
                u.Path = @"HKU\" + sid + @"\SOFTWARE\Policies";
                u.Scope = "User";
                u.Sid = sid;
                u.Hive = @"HKU\" + sid;
                roots.Add(u);
            }

            int budget = MaxRegistryValues;
            foreach (PolicyRoot root in roots)
            {
                if (budget <= 0) break;
                PolicyRoot rt = root;
                Walk(reg, rt.Path, 0, delegate (string path, string name, RegValue v)
                {
                    // User Group Policy is only asked for when the user has policy values, because each query can take time.
                    if (!rt.RsopRead) ReadUserRsop(rt, users, s);

                    RegistryEntry e = new RegistryEntry();
                    e.Path = path;
                    e.Name = name;
                    e.Kind = v.Kind;
                    e.Data = v.Data;
                    s.PolicyRegistry.Add(e);

                    string rel = path.Substring(rt.Path.Length).TrimStart('\\');
                    string polKey = @"Software\Policies" + (rel.Length > 0 ? "\\" + rel : "");
                    PolicySetting p = new PolicySetting();
                    p.Layer = Layers.Registry;
                    p.Scope = rt.Scope;
                    p.UserSid = rt.Sid;
                    p.Area = rel;
                    p.Name = name.Length == 0 ? "(Default)" : name;
                    p.Value = v.Data;
                    p.ValueKind = v.Kind;
                    p.RegistryPath = path;
                    AdmxPolicy a = catalog.ForValue(polKey, name);
                    if (a != null)
                    {
                        p.FriendlyName = a.DisplayName;
                        p.Description = a.Explain;
                    }

                    List<RsopValue> rows;
                    PolicySetting m = null;
                    if (rt.Gpo != null && rt.Gpo.TryGetValue(polKey + "|" + name, out rows) && rows.Count > 0)
                    {
                        p.Source = Sources.GroupPolicy;
                        p.SourceDetail = rows[0].GpoName;
                        foreach (RsopValue r in rows)
                        {
                            Contribution c = new Contribution();
                            c.Source = Sources.GroupPolicy;
                            c.Detail = r.GpoName + " (precedence " + r.Precedence.ToString(CultureInfo.InvariantCulture) + ")";
                            c.Value = r.Data;
                            c.RegistryPath = rt.Hive + "\\" + r.Key.Trim('\\');
                            c.Wins = r == rows[0];
                            p.Contributions.Add(c);
                        }
                    }
                    else if (a != null && (m = MdmFor(mdmByAdmx, a, rt)) != null)
                    {
                        p.Source = Sources.MdmAdmx;
                        p.SourceDetail = m.Area + "/" + m.Name;
                        Contribution c = new Contribution();
                        c.Source = m.Source ?? Sources.Unknown;
                        c.Detail = "MDM setting " + m.Area + "/" + m.Name;
                        c.Value = m.Value;
                        c.RegistryPath = m.RegistryPath;
                        c.Wins = true;
                        p.Contributions.Add(c);
                    }
                    else if (rt.RsopOk)
                    {
                        p.Source = Sources.Unmanaged;
                        p.Add(FindingKinds.Unmanaged, "No Group Policy object sets this value, and PolicyVice found no ADMX-backed MDM setting for it. It may be left behind (tattooed), or written by a script, an app or an MDM setting that PolicyVice cannot map.");
                    }
                    else
                    {
                        p.Source = Sources.Unknown;
                        p.SourceDetail = rt.Scope == "Device"
                            ? "Resultant Set of Policy was not available"
                            : "User Group Policy not available" + (string.IsNullOrEmpty(rt.RsopNote) ? "" : ": " + rt.RsopNote.TrimEnd('.'));
                    }
                    if (string.IsNullOrEmpty(p.FriendlyName)) p.FriendlyName = Txt.SplitCamel(p.Name);
                    s.Settings.Add(p);
                    return --budget > 0;
                });
            }
            if (budget <= 0) Note(s, "Only the first " + MaxRegistryValues.ToString(CultureInfo.InvariantCulture) + " values under SOFTWARE\\Policies were read.");
        }

        static PolicySetting MdmFor(Dictionary<AdmxPolicy, List<PolicySetting>> mdmByAdmx, AdmxPolicy a, PolicyRoot root)
        {
            List<PolicySetting> l;
            if (!mdmByAdmx.TryGetValue(a, out l)) return null;
            foreach (PolicySetting m in l)
            {
                if (m.Scope != root.Scope) continue;
                if (root.Scope == "User" && root.Sid != null && !string.Equals(m.UserSid, root.Sid, StringComparison.OrdinalIgnoreCase)) continue;
                return m;
            }
            return null;
        }

        delegate bool ValueVisitor(string path, string name, RegValue v);

        static bool Walk(IRegSource reg, string path, int depth, ValueVisitor visit)
        {
            if (depth > 16) return true;
            foreach (string name in reg.ValueNames(path))
            {
                RegValue v = reg.Get(path, name);
                if (v != null && !visit(path, name, v)) return false;
            }
            foreach (string sub in reg.SubKeys(path))
                if (!Walk(reg, path + "\\" + sub, depth + 1, visit)) return false;
            return true;
        }

        static void ReadErrors(IEventSource events, Snapshot s, CollectOptions opt)
        {
            List<EventItem> items = events.Read(MdmChannel, opt.NowUtc.AddDays(-opt.EventDays), true);
            ISourceNote sn = events as ISourceNote;
            if (sn != null && !string.IsNullOrEmpty(sn.Note)) Note(s, "MDM events: " + sn.Note);
            if (items == null) return;
            foreach (EventItem it in items)
            {
                if (it == null) continue;
                try { s.Errors.Add(ParseEvent(it)); }
                catch (Exception) { }
            }
        }

        // Reads the CSP URI, area, policy and result from an event of the DeviceManagement Admin channel.
        public static MdmError ParseEvent(EventItem it)
        {
            MdmError e = new MdmError();
            e.Time = it.Time;
            e.EventId = it.Id;
            e.Level = it.Level;
            e.Message = it.Message ?? "";
            string all = e.Message;
            if (it.Properties != null && it.Properties.Length > 0) all += " " + string.Join(" ", it.Properties);

            Match m = RxUri.Match(e.Message);
            e.CspUri = m.Success && m.Groups[1].Value.Trim().Length > 0 ? m.Groups[1].Value.Trim() : null;
            if (string.IsNullOrEmpty(e.CspUri))
            {
                Match l = RxUriLoose.Match(all);
                if (l.Success) e.CspUri = l.Value.TrimEnd('.');
            }
            Match r = RxResult.Match(e.Message);
            if (r.Success && r.Groups[1].Value.Trim().Length > 0) e.Result = r.Groups[1].Value.Trim();
            else
            {
                // Without a Result label, only a failure HRESULT counts, not a value such as 0x00000002.
                foreach (Match h in RxHex.Matches(e.Message))
                    if (RxHresult.IsMatch(h.Value)) e.Result = h.Value;
            }
            string code = PropertyHresult(it.Properties);
            if (code != null)
            {
                if (string.IsNullOrEmpty(e.Result)) e.Result = code;
                else if (e.Result.IndexOf(code, StringComparison.OrdinalIgnoreCase) < 0 && !RxHex.IsMatch(e.Result)) e.Result += " (" + code + ")";
            }
            ParseUri(e);

            // "MDM PolicyManager: Set policy ..., Policy: (Name), Area: (Area), ..., Current User: (Device|SID)" has no CSP URI.
            if (string.IsNullOrEmpty(e.Area))
            {
                Dictionary<string, string> f = Fields(e.Message);
                string policy, area, user;
                if (f.TryGetValue("Policy", out policy) && f.TryGetValue("Area", out area) && policy.Length > 0 && area.Length > 0)
                {
                    e.Area = area;
                    e.Name = policy;
                    bool isUser = f.TryGetValue("Current User", out user) && RxSid.IsMatch(user);
                    e.Scope = isUser ? "User" : "Device";
                    if (string.IsNullOrEmpty(e.CspUri)) e.CspUri = (isUser ? "./User" : "./Device") + "/Vendor/MSFT/Policy/Config/" + area + "/" + policy;
                }
            }
            return e;
        }

        static Dictionary<string, string> Fields(string message)
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(message)) return d;
            foreach (Match m in RxField.Matches(message))
            {
                string k = m.Groups[1].Value.Trim();
                if (!d.ContainsKey(k)) d[k] = m.Groups[2].Value.Trim();
            }
            return d;
        }

        // The last event property that looks like a failure HRESULT, such as 0x80070057.
        static string PropertyHresult(string[] props)
        {
            if (props == null) return null;
            for (int i = props.Length - 1; i >= 0; i--)
            {
                string p = props[i] == null ? "" : props[i].Trim();
                if (RxHresult.IsMatch(p)) return "0x" + p.Substring(2).ToUpperInvariant();
            }
            return null;
        }

        public static void ParseUri(MdmError e)
        {
            if (string.IsNullOrEmpty(e.CspUri)) return;
            string u = e.CspUri;
            e.Scope = u.StartsWith("./User", StringComparison.OrdinalIgnoreCase) ? "User" : "Device";
            foreach (string marker in new string[] { "/Policy/Config/", "/Policy/Result/" })
            {
                int i = u.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (i < 0) continue;
                string[] parts = u.Substring(i + marker.Length).Split('/');
                if (parts.Length >= 2)
                {
                    e.Area = parts[0];
                    e.Name = parts[1];
                }
                return;
            }
        }

        // What decides between MDM and Group Policy for a setting. Only claims what Microsoft documents.
        static string WinsNote(Snapshot s, IRegSource reg, PolicySetting mdm, string area)
        {
            if (mdm != null && mdm.Scope == "User")
                return " MDMWinsOverGP is a device setting, and Microsoft does not document whether it covers user settings.";
            if (mdm != null && mdm.Area != null && mdm.Area.IndexOf("~Policy~", StringComparison.OrdinalIgnoreCase) > 0)
                return " This is ingested ADMX. Microsoft documents MDMWinsOverGP for Policy CSP settings only, so there is no guarantee which one wins.";
            if (string.Equals(area, "Update", StringComparison.OrdinalIgnoreCase))
            {
                RegValue ign = reg.Get(PolicyManager + @"\current\device\Update", "IgnoreWindowsUpdateGroupPolicies");
                if (ign != null && ign.Data == "1") return " IgnoreWindowsUpdateGroupPolicies is on, so Group Policy for Windows Update is ignored.";
                return " For Windows Update, Microsoft recommends IgnoreWindowsUpdateGroupPolicies over MDMWinsOverGP, and it is not on.";
            }
            return s.MdmWinsOverGp
                ? " MDMWinsOverGP is on. It blocks the Group Policy value only for Policy CSP settings that have an equivalent Group Policy."
                : " MDMWinsOverGP is off, so there is no guarantee which one wins.";
        }

        static void Correlate(IRegSource reg, Snapshot s, AdmxCatalog catalog)
        {
            // Names, value meanings and the conflicts that can be matched setting by setting.
            Enricher.Apply(s, CspCatalog.Embedded(), catalog, delegate (PolicySetting m) { return WinsNote(s, reg, m, m.Area); });

            // Group Policy in an area that MDM also configures, when no exact match was found above.
            for (int i = 0; i < Overlaps.GetLength(0); i++)
            {
                string area = Overlaps[i, 0], key = Overlaps[i, 1];
                int mdm = 0;
                foreach (PolicySetting p in s.Settings)
                    if (p.Layer == Layers.Mdm && p.Scope == "Device" && string.Equals(p.Area, area, StringComparison.OrdinalIgnoreCase)) mdm++;
                if (mdm == 0) continue;
                string note = WinsNote(s, reg, null, area);
                foreach (PolicySetting p in s.Settings)
                {
                    if (p.Layer != Layers.Registry || p.Source != Sources.GroupPolicy || p.Scope != "Device") continue;
                    if (!(string.Equals(p.Area, key, StringComparison.OrdinalIgnoreCase) || p.Area.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase))) continue;
                    if (p.Has(FindingKinds.Conflict)) continue;
                    p.Add(FindingKinds.Conflict, "MDM also configures the " + area + " area (" + mdm.ToString(CultureInfo.InvariantCulture) + " settings). Check that both do not set the same behaviour." + note);
                }
            }

            foreach (MdmError e in s.Errors)
            {
                if (e.Level != "Error" || string.IsNullOrEmpty(e.Area)) continue;
                foreach (PolicySetting p in s.Settings)
                {
                    if (p.Layer != Layers.Mdm || p.Scope != e.Scope) continue;
                    if (!string.Equals(p.Area, e.Area, StringComparison.OrdinalIgnoreCase) || !string.Equals(p.Name, e.Name, StringComparison.OrdinalIgnoreCase)) continue;
                    p.Add(FindingKinds.Error, "Event " + e.EventId + " at " + e.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + ": " + (string.IsNullOrEmpty(e.Result) ? "failed" : e.Result));
                }
            }
        }

        static bool IsSuffix(string name)
        {
            foreach (string sfx in Suffixes) if (name.EndsWith(sfx, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static string ScopeKey(string scope, string sid, string area, string name)
        {
            return scope + "|" + (sid ?? "") + "|" + area + "|" + name;
        }

        static bool SameGuid(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            return string.Equals(a.Trim('{', '}'), b.Trim('{', '}'), StringComparison.OrdinalIgnoreCase);
        }

        static string Str(RegValue v)
        {
            return v == null ? null : v.Data;
        }

        static int Int(RegValue v)
        {
            int n;
            return v != null && int.TryParse(v.Data, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0;
        }
    }
}
