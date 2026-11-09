namespace PolicyVice
{
    using System;
    using System.Collections.Generic;

    // Adds what Microsoft's Policy CSP documentation knows to a snapshot: names, value meanings, the Group Policy
    // counterpart of each MDM setting, and conflicts where MDM and Group Policy set the same policy.
    public static class Enricher
    {
        public const string WinsOn = " MDMWinsOverGP is on, so Windows blocks the Group Policy value for Policy CSP settings that have a Group Policy equivalent.";
        public const string WinsOff = " MDMWinsOverGP is off, so which value applies depends on the setting and on which was applied last.";

        public static void Apply(Snapshot s, CspCatalog csp, AdmxCatalog admx)
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
            try { Conflicts(s, csp, admx); }
            catch (Exception) { }
        }

        static void Describe(PolicySetting p, CspCatalog csp)
        {
            CspEntry e = csp.Find(p.Area, p.Name);
            bool admxBacked = IsAdmxValue(p.Value);
            if (admxBacked) p.ValueMeaning = p.Value.TrimStart().StartsWith("<disabled", StringComparison.OrdinalIgnoreCase) ? "Disabled" : "Enabled";
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
            if (plainName && (e.AdmxBacked || p.Area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrEmpty(e.FriendlyName))
                p.FriendlyName = e.FriendlyName;
        }

        static void Conflicts(Snapshot s, CspCatalog csp, AdmxCatalog admx)
        {
            Dictionary<string, PolicySetting> mdm = new Dictionary<string, PolicySetting>(StringComparer.OrdinalIgnoreCase);
            foreach (PolicySetting p in s.Settings)
                if (p.Layer == Layers.Mdm) mdm[p.Scope + "|" + (p.UserSid ?? "") + "|" + p.Area + "|" + p.Name] = p;

            string wins = s.MdmWinsOverGp ? WinsOn : WinsOff;
            foreach (PolicySetting g in s.Settings)
            {
                if (g.Layer != Layers.Registry || g.Source != Sources.GroupPolicy) continue;
                string key = @"Software\Policies" + (string.IsNullOrEmpty(g.Area) ? "" : "\\" + g.Area);
                string valueName = g.Name == "(Default)" ? "" : g.Name;
                List<PolicySetting> matches = new List<PolicySetting>();

                // The ADMX policy that writes this value, and the MDM settings that map to that policy.
                AdmxPolicy a = admx.ForValue(key, valueName);
                if (a != null)
                {
                    foreach (CspEntry e in csp.FindByAdmx(a.File, a.Name)) Collect(mdm, g, e.Area, e.Name, matches);
                    foreach (PolicySetting m in s.Settings)
                    {
                        if (m.Layer != Layers.Mdm || !m.Area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase) && m.Area.IndexOf("~Policy~", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        AdmxPolicy b = admx.ForMdm(m.Area, m.Name);
                        if (b != null && b == a && SameScope(m, g) && !matches.Contains(m)) matches.Add(m);
                    }
                }
                // Settings whose documented Group Policy registry value is exactly this one.
                foreach (CspEntry e in csp.FindByRegistry(key, valueName)) Collect(mdm, g, e.Area, e.Name, matches);

                foreach (PolicySetting m in matches)
                {
                    string gpo = string.IsNullOrEmpty(g.SourceDetail) ? "a GPO" : "GPO '" + g.SourceDetail + "'";
                    m.Add(FindingKinds.Conflict, "Group Policy also sets this: " + gpo + " sets " + g.Area + "\\" + g.Name + " = " + g.Value + "." + wins);
                    g.Add(FindingKinds.Conflict, "MDM also sets this: " + m.Area + "/" + m.Name + " = " + Txt.Short(m.DisplayValue, 120) + " (" + (m.Source ?? Sources.Unknown) + ")." + wins);
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
