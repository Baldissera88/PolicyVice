namespace PolicyVice
{
    using System;
    using System.Collections.Generic;

    // Adds what Microsoft's Policy CSP documentation knows to a snapshot: names, value meanings, the Group Policy
    // counterpart of each MDM setting, and conflicts where MDM and Group Policy set the same policy.
    public static class Enricher
    {
        public static void Apply(Snapshot s, CspCatalog csp, AdmxCatalog admx)
        {
            Apply(s, csp, admx, null);
        }

        // note gives the sentence about MDMWinsOverGP that ends each conflict message, for the MDM setting involved.
        public static void Apply(Snapshot s, CspCatalog csp, AdmxCatalog admx, Func<PolicySetting, string> note)
        {
            if (s == null) return;
            if (csp == null) csp = new CspCatalog();
            if (admx == null) admx = new AdmxCatalog();
            foreach (PolicySetting p in s.Settings)
            {
                try
                {
                    if (p.Layer == Layers.Mdm) Describe(p, csp);
                }
                catch (Exception) { }
            }
            if (note == null)
            {
                bool on = s.MdmWinsOverGp;
                note = delegate (PolicySetting m)
                {
                    return on
                        ? " MDMWinsOverGP is on. It blocks the Group Policy value only for Policy CSP settings that have an equivalent Group Policy."
                        : " MDMWinsOverGP is off, so there is no guarantee which one wins.";
                };
            }
            try { Conflicts(s, csp, admx, note); }
            catch (Exception) { }
        }

        static void Describe(PolicySetting p, CspCatalog csp)
        {
            CspEntry e = csp.Find(p.Area, p.Name);
            bool admxBacked = IsAdmxValue(p.Value);
            if (admxBacked) p.ValueMeaning = Names.AdmxValue(p.Value);
            if (e == null) return;
            if (!admxBacked) p.ValueMeaning = Short(CspCatalog.Meaning(e, p.Value));
            if (string.IsNullOrEmpty(p.Description)) p.Description = e.Description;
            if (!string.IsNullOrEmpty(e.AdmxPolicy) || !string.IsNullOrEmpty(e.GpPath))
            {
                p.GroupPolicyName = string.IsNullOrEmpty(e.FriendlyName) ? e.AdmxPolicy : e.FriendlyName;
                p.GroupPolicyPath = e.GpPath;
            }
            // ADMX-backed settings carry the Group Policy name. Other Policy CSP settings keep their own name, because the
            // Group Policy counterpart can mean the opposite (AllowRealtimeMonitoring and "Turn off real-time protection").
            bool plainName = string.IsNullOrEmpty(p.FriendlyName) || p.FriendlyName == Txt.SplitCamel(p.Name);
            // Security options and user rights carry the same names as in Group Policy, such as "Interactive logon: Don't display last signed-in".
            bool sameAsGp = string.Equals(p.Area, "LocalPoliciesSecurityOptions", StringComparison.OrdinalIgnoreCase) || string.Equals(p.Area, "UserRights", StringComparison.OrdinalIgnoreCase);
            if (plainName && (e.AdmxBacked || sameAsGp || p.Area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrEmpty(e.FriendlyName))
                p.FriendlyName = e.FriendlyName;
        }

        static void Conflicts(Snapshot s, CspCatalog csp, AdmxCatalog admx, Func<PolicySetting, string> note)
        {
            Dictionary<string, PolicySetting> mdm = new Dictionary<string, PolicySetting>(StringComparer.OrdinalIgnoreCase);
            Dictionary<AdmxPolicy, List<PolicySetting>> mdmByAdmx = new Dictionary<AdmxPolicy, List<PolicySetting>>();
            foreach (PolicySetting p in s.Settings)
            {
                if (p.Layer != Layers.Mdm) continue;
                mdm[p.Scope + "|" + (p.UserSid ?? "") + "|" + p.Area + "|" + p.Name] = p;
                AdmxPolicy b = Collector.AdmxFor(p, admx, csp);
                if (b == null) continue;
                List<PolicySetting> l;
                if (!mdmByAdmx.TryGetValue(b, out l)) { l = new List<PolicySetting>(); mdmByAdmx[b] = l; }
                l.Add(p);
            }

            foreach (PolicySetting g in s.Settings)
            {
                if (g.Layer != Layers.Registry || g.Source != Sources.GroupPolicy) continue;
                string key = g.PolicyKey ?? (@"Software\Policies" + (string.IsNullOrEmpty(g.Area) ? "" : "\\" + g.Area));
                string valueName = g.Name == "(Default)" ? "" : g.Name;
                List<PolicySetting> matches = new List<PolicySetting>();

                // The ADMX policy that writes this value, and the MDM settings that map to that policy:
                // ADMX_ areas and ingested ADMX through the local ADMX files, other areas through the documentation.
                AdmxPolicy a = admx.ForValue(key, valueName);
                if (a != null)
                {
                    List<PolicySetting> same;
                    if (mdmByAdmx.TryGetValue(a, out same))
                        foreach (PolicySetting m in same)
                            if (SameScope(m, g) && !matches.Contains(m)) matches.Add(m);
                    foreach (CspEntry e in csp.FindByAdmx(a.File, a.Name)) Collect(mdm, g, e.Area, e.Name, matches);
                }
                // Settings whose documented Group Policy registry value is exactly this one.
                foreach (CspEntry e in csp.FindByRegistry(key, valueName)) Collect(mdm, g, e.Area, e.Name, matches);

                foreach (PolicySetting m in matches)
                {
                    string n = note(m) ?? "";
                    string gpo = string.IsNullOrEmpty(g.SourceDetail) ? "Group Policy" : "Group Policy '" + g.SourceDetail + "'";
                    m.Add(FindingKinds.Conflict, "Also set by " + gpo + " (" + g.Area + "\\" + g.Name + " = " + g.Value + ")." + n);
                    g.Add(FindingKinds.Conflict, "Also set by MDM (" + m.Area + "/" + m.Name + " = " + Txt.Short(m.DisplayValue, 120) + ", " + (m.Source ?? Sources.Unknown) + ")." + n);
                }
            }
        }

        static void Collect(Dictionary<string, PolicySetting> mdm, PolicySetting g, string area, string name, List<PolicySetting> into)
        {
            PolicySetting m;
            if (mdm.TryGetValue(g.Scope + "|" + (g.Scope == "User" ? g.UserSid ?? "" : "") + "|" + area + "|" + name, out m) && !into.Contains(m)) into.Add(m);
        }

        static bool SameScope(PolicySetting m, PolicySetting g)
        {
            if (m.Scope != g.Scope) return false;
            return m.Scope != "User" || string.Equals(m.UserSid, g.UserSid, StringComparison.OrdinalIgnoreCase);
        }

        static bool IsAdmxValue(string v)
        {
            if (string.IsNullOrEmpty(v)) return false;
            string t = v.TrimStart();
            return t.StartsWith("<enabled", StringComparison.OrdinalIgnoreCase) || t.StartsWith("<disabled", StringComparison.OrdinalIgnoreCase);
        }

        // The first sentence of a documented meaning, short enough for a grid cell.
        public static string Short(string meaning)
        {
            if (string.IsNullOrEmpty(meaning)) return null;
            string m = meaning.Trim();
            int dot = m.IndexOf(". ", StringComparison.Ordinal);
            if (dot > 0) m = m.Substring(0, dot);
            m = m.TrimEnd('.');
            if (m.Length > 70) m = m.Substring(0, 69).TrimEnd() + "…";
            return m;
        }
    }
}
