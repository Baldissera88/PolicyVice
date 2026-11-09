namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Text;

    public static class Report
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public static void Csv(Snapshot s, string path)
        {
            StringBuilder b = new StringBuilder();
            b.AppendLine("Layer,Scope,User SID,Area,Name,Friendly name,Value,Meaning,Type,Source,Source detail,Findings,Registry path,CSP URI,Group Policy counterpart");
            foreach (PolicySetting p in s.Settings)
            {
                List<string> f = new List<string>();
                foreach (Finding x in p.Findings) f.Add(x.Kind + ": " + x.Message);
                b.AppendLine(string.Join(",", new string[]
                {
                    C(p.Layer), C(p.Scope), C(p.UserSid), C(p.Area), C(p.Name), C(p.FriendlyName), C(p.Value), C(p.ValueMeaning), C(p.ValueKind),
                    C(p.Source), C(p.SourceDetail), C(string.Join(" | ", f.ToArray())), C(p.RegistryPath), C(p.CspUri), C(p.GroupPolicyName)
                }));
            }
            File.WriteAllText(path, b.ToString(), new UTF8Encoding(true));
        }

        static string C(string v)
        {
            if (v == null) return "";
            if (v.Length > 0 && "=+-@".IndexOf(v[0]) >= 0) v = "'" + v;
            if (v.IndexOfAny(new char[] { ',', '"', '\n', '\r' }) < 0) return v;
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }

        static string H(string v)
        {
            return WebUtility.HtmlEncode(v ?? "");
        }

        static void Head(StringBuilder b, string title)
        {
            b.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            b.Append("<title>").Append(H(title)).Append("</title><style>");
            b.Append(":root{--bg:#EEF1F6;--card:#fff;--alt:#F5F7FA;--line:#DCE1E8;--text:#111418;--t2:#454B54;--t3:#6E7580;--acc:#005FB8;--err:#C42B1C;--errbg:#FDE3E5;--warn:#9D5D00;--warnbg:#FFF1C7;--ok:#0F7B0F}");
            b.Append("@media(prefers-color-scheme:dark){:root{--bg:#191B20;--card:#24272D;--alt:#2C3037;--line:#363A42;--text:#F5F7FA;--t2:#D3D7DE;--t3:#A2A8B2;--acc:#60CDFF;--err:#FF99A4;--errbg:#47292B;--warn:#FCE100;--warnbg:#45391D;--ok:#6CCB5F}}");
            b.Append("body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 'Segoe UI Variable Text','Segoe UI',system-ui,sans-serif}");
            b.Append("main{max-width:1280px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}");
            b.Append(".meta{color:var(--t3);margin-bottom:16px}.cards{display:flex;flex-wrap:wrap;gap:10px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:110px}");
            b.Append(".card b{display:block;font-size:22px}.card span{color:var(--t3);font-size:12px}.card.bad b{color:var(--err)}.card.warn b{color:var(--warn)}");
            b.Append(".wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:13px}");
            b.Append("th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--alt);font-weight:600;white-space:nowrap}");
            b.Append("td.v{font-family:'Cascadia Mono',Consolas,monospace;word-break:break-all;max-width:360px}.f{display:inline-block;border-radius:4px;padding:0 6px;margin:1px 4px 1px 0;font-size:12px}");
            b.Append(".f.Conflict,.f.Error{background:var(--errbg);color:var(--err)}.f.Orphan,.f.Unmanaged{background:var(--warnbg);color:var(--warn)}.f.Added{color:var(--ok)}");
            b.Append(".note{color:var(--t2)}footer{margin-top:28px;color:var(--t3);font-size:12px}</style></head><body><main>");
        }

        public static string Html(Snapshot s)
        {
            StringBuilder b = new StringBuilder();
            Head(b, "PolicyVice report - " + s.Computer);
            b.Append("<h1>PolicyVice report</h1><div class=\"meta\">").Append(H(s.Computer)).Append(" &middot; ").Append(H(s.OsVersion))
             .Append(" &middot; ").Append(H(s.TakenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", Inv)))
             .Append(" &middot; ").Append(s.Elevated ? "run as administrator" : "run without administrator rights").Append("</div>");
            b.Append("<div class=\"cards\">");
            Card(b, s.Enrollments.Count, "Enrollments", null);
            Card(b, s.CountLayer(Layers.Mdm), "MDM settings", null);
            Card(b, s.CountSource(Sources.GroupPolicy), "Group Policy values", null);
            Card(b, s.Count(FindingKinds.Conflict), "Conflicts", "bad");
            Card(b, s.Count(FindingKinds.Error), "Settings with errors", "bad");
            Card(b, s.Count(FindingKinds.Orphan), "Orphans", "warn");
            Card(b, s.Count(FindingKinds.Unmanaged), "Unmanaged values", "warn");
            List<ImeItem> ime = new List<ImeItem>();
            if (s.Intune != null) foreach (ImeItem i in s.Intune) if (i != null) ime.Add(i);
            int failed = 0;
            foreach (ImeItem i in ime) if (i.Failed) failed++;
            if (ime.Count > 0) Card(b, failed, "Failed apps and scripts", "bad");
            b.Append("</div><p class=\"note\">MDMWinsOverGP is ").Append(s.MdmWinsOverGp ? "on" : "off").Append(".");
            if (!string.IsNullOrEmpty(s.RsopNote)) b.Append(" ").Append(H(s.RsopNote));
            b.Append("</p>");

            List<PolicySetting> flagged = new List<PolicySetting>();
            foreach (PolicySetting p in s.Settings) if (p.Findings.Count > 0) flagged.Add(p);
            if (flagged.Count > 0)
            {
                b.Append("<h2>Findings</h2>");
                Settings(b, flagged, true);
            }

            if (s.Enrollments.Count > 0)
            {
                b.Append("<h2>Enrollments</h2><div class=\"wrap\"><table><tr><th>Provider</th><th>User</th><th>Type</th><th>State</th><th>Enrollment ID</th></tr>");
                foreach (Enrollment e in s.Enrollments)
                    b.Append("<tr><td>").Append(H(e.ProviderName)).Append("</td><td>").Append(H(e.Upn)).Append("</td><td>").Append(e.EnrollmentType)
                     .Append("</td><td>").Append(e.EnrollmentState).Append("</td><td class=\"v\">").Append(H(e.Id)).Append("</td></tr>");
                b.Append("</table></div>");
            }

            if (ime.Count > 0)
            {
                // Failed first, then by kind and name. A stable sort keeps the collector's order within each group.
                List<KeyValuePair<int, ImeItem>> order = new List<KeyValuePair<int, ImeItem>>();
                for (int i = 0; i < ime.Count; i++) order.Add(new KeyValuePair<int, ImeItem>(i, ime[i]));
                order.Sort(delegate (KeyValuePair<int, ImeItem> x, KeyValuePair<int, ImeItem> y)
                {
                    if (x.Value.Failed != y.Value.Failed) return x.Value.Failed ? -1 : 1;
                    int c = string.Compare(x.Value.Kind, y.Value.Kind, StringComparison.OrdinalIgnoreCase);
                    if (c == 0) c = string.Compare(ImeName(x.Value), ImeName(y.Value), StringComparison.OrdinalIgnoreCase);
                    return c != 0 ? c : x.Key.CompareTo(y.Key);
                });
                b.Append("<h2>Intune apps and scripts</h2><div class=\"wrap\"><table><tr><th>Kind</th><th>Name</th><th>Status</th><th>Error</th><th>Time</th><th>User</th></tr>");
                foreach (KeyValuePair<int, ImeItem> kv in order)
                {
                    ImeItem i = kv.Value;
                    b.Append("<tr><td>").Append(H(i.Kind)).Append("</td><td title=\"").Append(H(i.Id)).Append("\">").Append(H(ImeName(i)));
                    if (!string.IsNullOrEmpty(i.Detail)) b.Append("<br><span class=\"note\">").Append(H(Txt.Short(i.Detail, 400))).Append("</span>");
                    b.Append("</td><td>");
                    if (i.Failed) b.Append("<span class=\"f Error\">").Append(H(string.IsNullOrEmpty(i.Status) ? "Failed" : i.Status)).Append("</span>");
                    else b.Append(H(i.Status));
                    b.Append("</td><td class=\"v\">").Append(H(i.ErrorCode)).Append("</td><td>")
                     .Append(i.Time.HasValue ? H(i.Time.Value.ToString("yyyy-MM-dd HH:mm:ss", Inv)) : "").Append("</td><td>").Append(H(i.User)).Append("</td></tr>");
                }
                b.Append("</table></div>");
            }

            if (s.Device != null && s.Device.Items != null && s.Device.Items.Count > 0)
            {
                List<string> groups = new List<string>();
                foreach (InfoItem i in s.Device.Items) if (i != null && !groups.Contains(i.Group ?? "")) groups.Add(i.Group ?? "");
                b.Append("<h2>Device</h2><div class=\"wrap\"><table>");
                foreach (string g in groups)
                {
                    b.Append("<tr><th colspan=\"2\">").Append(H(g.Length == 0 ? "Other" : g)).Append("</th></tr>");
                    foreach (InfoItem i in s.Device.Items)
                        if (i != null && (i.Group ?? "") == g)
                            b.Append("<tr><td style=\"width:240px\">").Append(H(i.Label)).Append("</td><td>").Append(H(i.Value)).Append("</td></tr>");
                }
                b.Append("</table></div>");
            }

            b.Append("<h2>All settings</h2>");
            Settings(b, s.Settings, false);

            if (s.Errors.Count > 0)
            {
                b.Append("<h2>MDM events, last ").Append(s.EventDays).Append(" days</h2><div class=\"wrap\"><table><tr><th>Time</th><th>Event</th><th>Level</th><th>CSP URI</th><th>Result</th></tr>");
                foreach (MdmError e in s.Errors)
                    b.Append("<tr><td>").Append(e.Time.ToString("yyyy-MM-dd HH:mm:ss", Inv)).Append("</td><td>").Append(e.EventId).Append("</td><td>").Append(H(e.Level))
                     .Append("</td><td class=\"v\">").Append(H(e.CspUri)).Append("</td><td>").Append(H(e.Result ?? Txt.Short(e.Message, 160))).Append("</td></tr>");
                b.Append("</table></div>");
            }
            Foot(b, s.ToolVersion);
            return b.ToString();
        }

        public static string DiffHtml(string titleA, string titleB, List<Change> changes, string version)
        {
            StringBuilder b = new StringBuilder();
            Head(b, "PolicyVice comparison");
            b.Append("<h1>PolicyVice comparison</h1><div class=\"meta\">").Append(H(titleA)).Append(" &rarr; ").Append(H(titleB)).Append("</div>");
            if (changes.Count == 0) b.Append("<p>No differences.</p>");
            else
            {
                b.Append("<div class=\"wrap\"><table><tr><th>Change</th><th>Layer</th><th>Scope</th><th>Area</th><th>Setting</th><th>Before</th><th>After</th><th>Source</th></tr>");
                foreach (Change c in changes)
                {
                    string src = c.OldSource == c.NewSource || c.OldSource == null ? c.NewSource : c.NewSource == null ? c.OldSource : c.OldSource + " → " + c.NewSource;
                    b.Append("<tr><td><span class=\"f ").Append(c.Kind == Differ.Removed ? "Error" : c.Kind == Differ.Changed ? "Orphan" : "Added").Append("\">").Append(c.Kind).Append("</span></td><td>")
                     .Append(H(c.Layer)).Append("</td><td>").Append(H(c.Scope)).Append("</td><td>").Append(H(c.Area)).Append("</td><td>").Append(H(c.Setting))
                     .Append("</td><td class=\"v\">").Append(H(c.OldValue)).Append("</td><td class=\"v\">").Append(H(c.NewValue)).Append("</td><td>").Append(H(src)).Append("</td></tr>");
                }
                b.Append("</table></div>");
            }
            Foot(b, version);
            return b.ToString();
        }

        static void Settings(StringBuilder b, List<PolicySetting> list, bool findings)
        {
            b.Append("<div class=\"wrap\"><table><tr><th>Layer</th><th>Scope</th><th>Area</th><th>Setting</th><th>Value</th><th>Source</th>");
            if (findings) b.Append("<th>Findings</th>");
            b.Append("</tr>");
            foreach (PolicySetting p in list)
            {
                b.Append("<tr><td>").Append(H(p.Layer)).Append("</td><td>").Append(H(p.Scope)).Append("</td><td>").Append(H(p.Area)).Append("</td><td title=\"").Append(H(p.Name)).Append("\">")
                 .Append(H(p.DisplayName)).Append("</td><td class=\"v\">").Append(H(Txt.Short(p.DisplayValue, 400))).Append("</td><td>").Append(H(p.Source));
                if (!string.IsNullOrEmpty(p.SourceDetail)) b.Append("<br><span class=\"note\">").Append(H(p.SourceDetail)).Append("</span>");
                b.Append("</td>");
                if (findings)
                {
                    b.Append("<td>");
                    foreach (Finding f in p.Findings) b.Append("<span class=\"f ").Append(H(f.Kind)).Append("\">").Append(H(f.Kind)).Append("</span>").Append(H(f.Message)).Append("<br>");
                    b.Append("</td>");
                }
                b.Append("</tr>");
            }
            b.Append("</table></div>");
        }

        static string ImeName(ImeItem i)
        {
            return string.IsNullOrEmpty(i.Name) ? i.Id : i.Name;
        }

        static void Card(StringBuilder b, int n, string label, string cls)
        {
            b.Append("<div class=\"card").Append(n > 0 && cls != null ? " " + cls : "").Append("\"><b>").Append(n).Append("</b><span>").Append(H(label)).Append("</span></div>");
        }

        static void Foot(StringBuilder b, string version)
        {
            b.Append("<footer>Made with PolicyVice ").Append(H(version)).Append(" by Daniel L. Baldissera.</footer></main></body></html>");
        }
    }
}
