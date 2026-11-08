namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text.RegularExpressions;

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
        const int MaxRegistryValues = 20000;

        static readonly string[] Suffixes = { "_ProviderSet", "_WinningProvider", "_LastWrite", "_ADMXInstanceData" };
        static readonly Regex RxUri = new Regex(@"CSP URI:\s*\(([^)]*)\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxUriLoose = new Regex(@"\./(?:Device/|User/)?Vendor/MSFT/[^\s,)""]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxResult = new Regex(@"Result:\s*\(([^)]*)\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RxHex = new Regex(@"0x[0-9A-Fa-f]{8}", RegexOptions.Compiled);
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
            if (catalog == null) catalog = new AdmxCatalog();
            Snapshot s = new Snapshot();
            s.ToolVersion = opt.Version;
            s.Computer = opt.Computer;
            s.UserName = opt.UserName;
            s.OsVersion = opt.OsVersion;
            s.Elevated = opt.Elevated;
            s.TakenUtc = opt.NowUtc;
            s.EventDays = opt.EventDays;

            ReadEnrollments(reg, s);
            try { s.Device = DeviceCollector.Collect(reg) ?? new DeviceInfo(); } catch (Exception) { s.Device = new DeviceInfo(); }
            try { s.Intune = ImeCollector.Collect(reg) ?? new List<ImeItem>(); } catch (Exception) { s.Intune = new List<ImeItem>(); }
            ReadAdmxInstalled(reg, s, catalog);
            ReadMdm(reg, s, catalog);
            RegValue wins = reg.Get(PolicyManager + @"\current\device\ControlPolicyConflict", "MDMWinsOverGP");
            s.MdmWinsOverGp = wins != null && wins.Data == "1";

            string note = null;
            List<RsopValue> gp = rsop != null ? rsop.ComputerValues(out note) : new List<RsopValue>();
            s.RsopAvailable = rsop != null && note == null;
            s.RsopNote = rsop == null ? "Resultant Set of Policy was not read." : note;
            ReadPolicyRegistry(reg, s, catalog, gp, opt);
            if (events != null && opt.EventDays > 0) ReadErrors(events, s, opt);
            Correlate(s, catalog);
            s.AccessDenied.AddRange(reg.Denied);
            s.Settings.Sort(delegate (PolicySetting a, PolicySetting b)
            {
                int c = string.CompareOrdinal(a.Layer, b.Layer);
                if (c != 0) return c;
                c = string.Compare(a.Area, b.Area, StringComparison.OrdinalIgnoreCase);
                return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            });
            return s;
        }

        static void ReadEnrollments(IRegSource reg, Snapshot s)
        {
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
                    string[] names = reg.ValueNames(ap);
                    foreach (string name in names)
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
                        p.WinningProvider = win != null ? win.Data : null;
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
                            c.Source = e == null ? "Provider" : e.IsIntune ? Sources.Intune : Sources.OtherMdm;
                            c.Detail = e == null || string.IsNullOrEmpty(e.Upn) ? "enrollment " + provider : e.Upn + ", enrollment " + provider;
                            c.ProviderId = provider;
                            c.Value = v == null ? "" : v.Data;
                            c.RegistryPath = ap;
                            c.Wins = SameGuid(provider, p.WinningProvider);
                            p.Contributions.Add(c);
                        }
                    }
                }
            }

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
                    p.SourceDetail = string.IsNullOrEmpty(e.Upn) ? e.Id : e.Upn;
                }
                else if (!string.IsNullOrEmpty(winner))
                {
                    p.Source = Sources.OtherMdm;
                    p.SourceDetail = "Provider " + winner;
                }
                else p.Source = Sources.Unknown;
                if (p.Contributions.Count == 0)
                    p.Add(FindingKinds.Orphan, "Set in PolicyManager\\current, but no provider sent it. A removed profile or enrollment may have left it behind.");
            }
        }

        static void ReadPolicyRegistry(IRegSource reg, Snapshot s, AdmxCatalog catalog, List<RsopValue> gp, CollectOptions opt)
        {
            Dictionary<string, List<RsopValue>> gpo = new Dictionary<string, List<RsopValue>>(StringComparer.OrdinalIgnoreCase);
            foreach (RsopValue r in gp)
            {
                if (r.Deleted) continue;
                string k = r.Key.Trim('\\') + "|" + (r.ValueName ?? "");
                List<RsopValue> l;
                if (!gpo.TryGetValue(k, out l)) { l = new List<RsopValue>(); gpo[k] = l; }
                l.Add(r);
            }

            Dictionary<AdmxPolicy, PolicySetting> mdmByAdmx = new Dictionary<AdmxPolicy, PolicySetting>();
            foreach (PolicySetting p in s.Settings)
            {
                if (p.Layer != Layers.Mdm) continue;
                AdmxPolicy a = catalog.ForMdm(p.Area, p.Name);
                if (a != null && !mdmByAdmx.ContainsKey(a)) mdmByAdmx[a] = p;
            }

            List<string[]> roots = new List<string[]>();
            roots.Add(new string[] { @"HKLM\SOFTWARE\Policies", "Device", null });
            roots.Add(new string[] { @"HKCU\SOFTWARE\Policies", "User", opt.CurrentUserSid });
            List<string> sids = new List<string>();
            foreach (PolicySetting p in s.Settings) if (p.UserSid != null && !sids.Contains(p.UserSid)) sids.Add(p.UserSid);
            foreach (string sid in sids)
                if (!string.Equals(sid, opt.CurrentUserSid, StringComparison.OrdinalIgnoreCase))
                    roots.Add(new string[] { @"HKU\" + sid + @"\SOFTWARE\Policies", "User", sid });

            int budget = MaxRegistryValues;
            foreach (string[] root in roots)
            {
                Walk(reg, root[0], 0, delegate (string path, string name, RegValue v)
                {
                    RegistryEntry e = new RegistryEntry();
                    e.Path = path;
                    e.Name = name;
                    e.Kind = v.Kind;
                    e.Data = v.Data;
                    s.PolicyRegistry.Add(e);

                    string rel = path.Substring(root[0].Length).TrimStart('\\');
                    string polKey = @"Software\Policies" + (rel.Length > 0 ? "\\" + rel : "");
                    PolicySetting p = new PolicySetting();
                    p.Layer = Layers.Registry;
                    p.Scope = root[1];
                    p.UserSid = root[2];
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
                    if (root[1] == "Device" && gpo.TryGetValue(polKey + "|" + name, out rows))
                    {
                        rows.Sort(delegate (RsopValue x, RsopValue y) { return x.Precedence.CompareTo(y.Precedence); });
                        p.Source = Sources.GroupPolicy;
                        p.SourceDetail = rows[0].GpoName;
                        foreach (RsopValue r in rows)
                        {
                            Contribution c = new Contribution();
                            c.Source = Sources.GroupPolicy;
                            c.Detail = r.GpoName + " (precedence " + r.Precedence + ")";
                            c.Value = r.Data;
                            c.RegistryPath = "HKLM\\" + r.Key;
                            c.Wins = r == rows[0];
                            p.Contributions.Add(c);
                        }
                    }
                    else
                    {
                        PolicySetting m;
                        if (a != null && mdmByAdmx.TryGetValue(a, out m) && (m.Scope == p.Scope))
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
                        else if (root[1] == "Device" && s.RsopAvailable)
                        {
                            p.Source = Sources.Unmanaged;
                            p.Add(FindingKinds.Unmanaged, "No Group Policy object and no MDM setting claims this value. It may be left behind (tattooed) or written by a script or an app.");
                        }
                        else
                        {
                            p.Source = Sources.Unknown;
                            p.SourceDetail = root[1] == "User" ? "User Group Policy is not read in this version" : "Resultant Set of Policy was not available";
                        }
                    }
                    if (string.IsNullOrEmpty(p.FriendlyName)) p.FriendlyName = Txt.SplitCamel(p.Name);
                    s.Settings.Add(p);
                    return --budget > 0;
                });
            }
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
            foreach (EventItem it in items)
            {
                MdmError e = new MdmError();
                e.Time = it.Time;
                e.EventId = it.Id;
                e.Level = it.Level;
                e.Message = it.Message ?? "";
                Match m = RxUri.Match(e.Message);
                e.CspUri = m.Success ? m.Groups[1].Value.Trim() : null;
                if (string.IsNullOrEmpty(e.CspUri))
                {
                    Match l = RxUriLoose.Match(e.Message);
                    if (l.Success) e.CspUri = l.Value.TrimEnd('.');
                }
                Match r = RxResult.Match(e.Message);
                if (r.Success) e.Result = r.Groups[1].Value.Trim();
                else
                {
                    Match h = RxHex.Match(e.Message);
                    if (h.Success) e.Result = h.Value;
                }
                ParseUri(e);
                s.Errors.Add(e);
            }
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

        static void Correlate(Snapshot s, AdmxCatalog catalog)
        {
            Dictionary<AdmxPolicy, List<PolicySetting>> gpByAdmx = new Dictionary<AdmxPolicy, List<PolicySetting>>();
            foreach (PolicySetting p in s.Settings)
            {
                if (p.Layer != Layers.Registry || p.Source != Sources.GroupPolicy) continue;
                AdmxPolicy a = catalog.ForValue(@"Software\Policies\" + p.Area, p.Name == "(Default)" ? "" : p.Name);
                if (a == null) continue;
                List<PolicySetting> l;
                if (!gpByAdmx.TryGetValue(a, out l)) { l = new List<PolicySetting>(); gpByAdmx[a] = l; }
                l.Add(p);
            }

            string winsNote = s.MdmWinsOverGp
                ? " MDMWinsOverGP is on, so MDM wins for Policy CSP settings it covers."
                : " MDMWinsOverGP is off, so whichever applies last sets the value.";
            foreach (PolicySetting m in s.Settings)
            {
                if (m.Layer != Layers.Mdm || m.Scope != "Device") continue;
                AdmxPolicy a = catalog.ForMdm(m.Area, m.Name);
                List<PolicySetting> gps;
                if (a == null || !gpByAdmx.TryGetValue(a, out gps)) continue;
                foreach (PolicySetting g in gps)
                {
                    m.Add(FindingKinds.Conflict, "Also set by Group Policy '" + g.SourceDetail + "' (" + g.Area + "\\" + g.Name + " = " + g.Value + ")." + winsNote);
                    g.Add(FindingKinds.Conflict, "Also set by MDM (" + m.Area + "/" + m.Name + ", " + (m.Source ?? Sources.Unknown) + ")." + winsNote);
                }
            }

            for (int i = 0; i < Overlaps.GetLength(0); i++)
            {
                string area = Overlaps[i, 0], key = Overlaps[i, 1];
                int mdm = 0;
                foreach (PolicySetting p in s.Settings)
                    if (p.Layer == Layers.Mdm && p.Scope == "Device" && string.Equals(p.Area, area, StringComparison.OrdinalIgnoreCase)) mdm++;
                if (mdm == 0) continue;
                foreach (PolicySetting p in s.Settings)
                {
                    if (p.Layer != Layers.Registry || p.Source != Sources.GroupPolicy) continue;
                    if (!(string.Equals(p.Area, key, StringComparison.OrdinalIgnoreCase) || p.Area.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase))) continue;
                    if (p.Has(FindingKinds.Conflict)) continue;
                    p.Add(FindingKinds.Conflict, "MDM also configures the " + area + " area (" + mdm.ToString(CultureInfo.InvariantCulture) + " settings). Check that both do not set the same behaviour." + winsNote);
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
