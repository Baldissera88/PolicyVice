namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    // Registry fake for the IME tests, with access denied and a counter for keys read.
    public sealed class ImeFakeRegistry : IRegSource
    {
        readonly Dictionary<string, Dictionary<string, RegValue>> keys = new Dictionary<string, Dictionary<string, RegValue>>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> denied = new List<string>();
        readonly List<string> deny = new List<string>();
        public bool Throw;

        public List<string> Denied
        {
            get { return denied; }
        }

        public void Set(string path, string name, string kind, string data)
        {
            Ensure(path)[name] = new RegValue(kind, data);
        }

        public void Sz(string path, string name, string data)
        {
            Set(path, name, "REG_SZ", data);
        }

        public void Dword(string path, string name, long data)
        {
            Set(path, name, "REG_DWORD", data.ToString());
        }

        public void Key(string path)
        {
            Ensure(path);
        }

        public void Deny(string path)
        {
            Ensure(path);
            deny.Add(path);
        }

        Dictionary<string, RegValue> Ensure(string path)
        {
            Dictionary<string, RegValue> v;
            if (!keys.TryGetValue(path, out v))
            {
                v = new Dictionary<string, RegValue>(StringComparer.OrdinalIgnoreCase);
                keys[path] = v;
                int i = path.LastIndexOf('\\');
                if (i > 0) Ensure(path.Substring(0, i));
            }
            return v;
        }

        bool Blocked(string path)
        {
            if (Throw) throw new InvalidOperationException("registry failure");
            foreach (string d in deny)
            {
                if (string.Equals(path, d, StringComparison.OrdinalIgnoreCase) || path.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    if (!denied.Contains(d)) denied.Add(d);
                    return true;
                }
            }
            return false;
        }

        public string[] SubKeys(string path)
        {
            if (Blocked(path)) return new string[0];
            List<string> l = new List<string>();
            string prefix = path + "\\";
            foreach (string k in keys.Keys)
            {
                if (!k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                string rest = k.Substring(prefix.Length);
                if (rest.IndexOf('\\') < 0) l.Add(rest);
            }
            l.Sort(StringComparer.OrdinalIgnoreCase);
            return l.ToArray();
        }

        public string[] ValueNames(string path)
        {
            if (Blocked(path)) return new string[0];
            Dictionary<string, RegValue> v;
            if (!keys.TryGetValue(path, out v)) return new string[0];
            return new List<string>(v.Keys).ToArray();
        }

        public RegValue Get(string path, string name)
        {
            if (Blocked(path)) return null;
            Dictionary<string, RegValue> v;
            RegValue r;
            return keys.TryGetValue(path, out v) && v.TryGetValue(name, out r) ? r : null;
        }
    }

    public static class ImeTests
    {
        const string Ime = @"HKLM\SOFTWARE\Microsoft\IntuneManagementExtension";
        const string Device = "00000000-0000-0000-0000-000000000000";
        const string Anna = "ddc3cf6e-3b3b-461c-a823-53196902d067";

        const string AppChrome = "e316127d-a9a4-4193-8f04-b07c37d1130f";
        const string AppVpn = "159aeebd-fe8a-4571-98ef-de8c72ff5ed5";
        const string AppTimeout = "d8981105-3d0e-4cf2-9d7f-6ab00c2573d2";
        const string AppReboot = "3f1f391f-381f-46a9-b987-6e344c6e95e2";
        const string AppNotApplicable = "a1a1a1a1-0000-4000-8000-000000000001";
        const string AppBroken = "a1a1a1a1-0000-4000-8000-000000000002";
        const string AppRetry = "a1a1a1a1-0000-4000-8000-000000000003";
        const string AppMsi = "a1a1a1a1-0000-4000-8000-000000000004";
        const string AppReportOnly = "a1a1a1a1-0000-4000-8000-000000000005";
        const string AppUninstall = "a1a1a1a1-0000-4000-8000-000000000006";

        const string ScriptOk = "29455f83-3916-4069-88ba-a8e51633e34a";
        const string ScriptBad = "56695a77-925a-4df0-be79-24ed039afa86";
        const string ScriptPending = "56695a77-925a-4df0-be79-24ed039afa87";

        const string RemFixed = "176b61ca-59e6-4af1-b852-13a3102c5578";
        const string RemNoIssue = "0e3a2b22-1801-46a9-8888-982aa7887d88";
        const string RemRecurred = "bbe9b83f-882c-4ae7-9a78-42fb2e0f5f65";
        const string RemError = "bbf7e139-fe9d-4783-80df-627b8e084059";
        const string RemBroken = "bbf7e139-fe9d-4783-80df-627b8e08405a";
        const string RemExecOnly = "bbf7e139-fe9d-4783-80df-627b8e08405b";

        static void Check(bool ok, string what)
        {
            T.Check(ok, "ime: " + what);
        }

        static string Cs(int applicability, int compliance, int desired, string errorCode, int context, int targetType)
        {
            return "{\"Applicability\":" + applicability + ",\"ComplianceState\":" + compliance + ",\"DesiredState\":" + desired
                + ",\"ErrorCode\":" + errorCode + ",\"TargetingMethod\":0,\"InstallContext\":" + context + ",\"TargetType\":" + targetType
                + ",\"ProductVersion\":null,\"AssignmentFilterIds\":null}";
        }

        static string Es(int enforcement, string errorCode)
        {
            return "{\"EnforcementState\":" + enforcement + ",\"ErrorCode\":" + errorCode + ",\"TargetingMethod\":0}";
        }

        // A Win32 app the way IME stores it: the JSON is a value in a subkey of the same name.
        static void App(ImeFakeRegistry r, string user, string key, string cs, string es, string updated)
        {
            string p = Ime + @"\Win32Apps\" + user + "\\" + key;
            r.Dword(p, "Intent", 3);
            if (updated != null) r.Sz(p, "LastUpdatedTimeUtc", updated);
            if (cs != null) r.Sz(p + @"\ComplianceStateMessage", "ComplianceStateMessage", cs);
            if (es != null) r.Sz(p + @"\EnforcementStateMessage", "EnforcementStateMessage", es);
        }

        static string RemResult(string policy, string user, int remediationStatus, int first, int remExit, int last, string preOutput, string remError, int errorCode)
        {
            return "{\"PolicyId\":\"" + policy + "\",\"UserId\":\"" + user + "\",\"PolicyHash\":null,\"Result\":3,\"ResultDetails\":null,\"InternalVersion\":1,"
                + "\"ErrorCode\":" + errorCode + ",\"ResultType\":1,\"PreRemediationDetectScriptOutput\":" + preOutput + ",\"PreRemediationDetectScriptError\":null,"
                + "\"RemediationScriptErrorDetails\":" + remError + ",\"PostRemediationDetectScriptOutput\":null,\"PostRemediationDetectScriptError\":null,"
                + "\"RemediationStatus\":" + remediationStatus + ",\"Info\":{\"RemediationExitCode\":" + remExit + ",\"FirstDetectExitCode\":" + first
                + ",\"LastDetectExitCode\":" + last + ",\"ErrorDetails\":null}}";
        }

        static void Rem(ImeFakeRegistry r, string user, string policy, string result, string lastExecution)
        {
            if (result != null) r.Sz(Ime + @"\SideCarPolicies\Scripts\Reports\" + user + "\\" + policy + @"_1\Result", "Result", result);
            if (lastExecution != null) r.Sz(Ime + @"\SideCarPolicies\Scripts\Execution\" + user + "\\" + policy + "_1", "LastExecution", lastExecution);
        }

        public static ImeFakeRegistry Sample()
        {
            ImeFakeRegistry r = new ImeFakeRegistry();
            string w = Ime + @"\Win32Apps";

            // Installed, device context. An older revision is still in the registry.
            App(r, Device, AppChrome + "_1", Cs(0, 1, 2, "0", 2, 2), Es(1000, "0"), "10/01/2026 02:38:27");
            App(r, Device, AppChrome + "_3", Cs(0, 1, 2, "0", 2, 2), Es(1000, "0"), "11/07/2026 08:15:00");

            // Installed, but not detected afterwards: 0x87D1041C (-2016345060).
            App(r, Device, AppVpn + "_2", Cs(0, 2, 2, "-2016345060", 2, 2), Es(5000, "-2016345060"), "11/08/2026 07:00:00");
            r.Sz(w + @"\" + Device + @"\GRS\5Nhyy9sV9nLHHCfYAgLksr+hQcuj2kFV2IGbNYi48u4=", AppVpn, "11/08/2026 07:00:05");

            // Install still running when IME stopped watching it: 0x87D300C9, user context.
            App(r, Anna, AppTimeout + "_1", Cs(0, 4, 2, "-2016214839", 1, 1), Es(5000, "-2016214839"), "2026-11-08T06:30:00.0000000Z");

            // Installed, reboot pending.
            App(r, Device, AppReboot + "_1", Cs(0, 2, 2, "0", 2, 2), Es(2008, "0"), "11/06/2026 12:00:00");

            // Requirements not met.
            App(r, Device, AppNotApplicable + "_1", Cs(1007, 2, 2, "0", 2, 2), Es(3000, "0"), "11/06/2026 12:00:00");

            // Malformed JSON: the compliance message is cut off, the enforcement message is garbage.
            App(r, Device, AppBroken + "_1", "{\"Applicability\":0,\"ComplianceState\":2,\"DesiredState\":2,\"ErrorCode\":-2147009", "not json at all", "garbage");

            // Failed, will retry immediately.
            App(r, Anna, AppRetry + "_1", Cs(0, 2, 2, "1618", 1, 1), Es(5999, "1618"), null);

            // MSI fatal error written as hex text.
            App(r, Device, AppMsi + "_1", Cs(0, 2, 2, "0", 2, 2), Es(5000, "\"0x80070643\""), "11/08/2026 05:00:00");

            // Uninstall assignment, app removed.
            App(r, Device, AppUninstall + "_1", Cs(0, 2, 1, "0", 2, 2), Es(1000, "0"), "11/08/2026 05:00:00");
            r.Dword(w + @"\" + Device + "\\" + AppUninstall + "_1", "Intent", 4);

            // Keys that are not users or apps.
            r.Sz(w + @"\OperationalState", "x", "1");
            r.Sz(w + @"\Reporting\" + Device + @"\" + AppVpn + @"\ReportCache\" + Device, "LastHashValue", "abc");
            r.Key(w + @"\" + Device + @"\not-an-app");

            // Status service report: one app that also has Win32Apps state, one without.
            string ssr = Ime + @"\SideCarPolicies\StatusServiceReports\" + Device;
            r.Sz(ssr + @"\" + AppVpn, "AppId", AppVpn);
            r.Sz(ssr + @"\" + AppVpn, "Status", "NotInstalled");
            r.Sz(ssr + @"\" + AppVpn, "ApplicabilityCode", "Applicable");
            r.Sz(ssr + @"\" + AppVpn, "ErrorCode", "-2016345060");
            r.Sz(ssr + @"\entry1", "AppId", AppReportOnly);
            r.Sz(ssr + @"\entry1", "Status", "Installed");
            r.Sz(ssr + @"\entry1", "ApplicabilityCode", "Applicable");
            r.Sz(ssr + @"\entry1", "ErrorCode", "0");

            // Platform scripts.
            string pol = Ime + @"\Policies";
            r.Sz(pol + @"\" + Device + @"\" + ScriptOk, "Result", "Success");
            r.Dword(pol + @"\" + Device + @"\" + ScriptOk, "ErrorCode", 0);
            r.Dword(pol + @"\" + Device + @"\" + ScriptOk, "DownloadCount", 1);
            r.Sz(pol + @"\" + Device + @"\" + ScriptOk, "LastUpdatedTimeUtc", "11/07/2026 22:10:41");
            r.Sz(pol + @"\" + Device + @"\" + ScriptOk, "ResultDetails", "{\"ExecutionMsg\":\"Configured OneDrive\\r\\nDone\",\"ErrorCode\":0}");
            r.Sz(pol + @"\" + Anna + @"\" + ScriptBad, "Result", "Failed");
            r.Dword(pol + @"\" + Anna + @"\" + ScriptBad, "ErrorCode", 1);
            r.Dword(pol + @"\" + Anna + @"\" + ScriptBad, "DownloadCount", 3);
            r.Sz(pol + @"\" + Anna + @"\" + ScriptBad, "LastUpdatedTimeUtc", "11/08/2026 06:01:00");
            r.Sz(pol + @"\" + Anna + @"\" + ScriptBad, "ResultDetails", "{\"ExecutionMsg\":\"Access to the path 'C:\\\\Windows\\\\x' is denied.\"");
            r.Key(pol + @"\" + Anna + @"\" + ScriptPending);

            // Remediations.
            Rem(r, Device, RemFixed, RemResult(RemFixed, Device, 1, 1, 0, 0, "\"Two extra admins found\"", "null", 0), "11/08/2026 06:55:46");
            Rem(r, Device, RemNoIssue, RemResult(RemNoIssue, Device, 4, 0, 0, 0, "\"86\"", "null", 0), "11/08/2026 06:56:00");
            Rem(r, Anna, RemRecurred, RemResult(RemRecurred, Anna, 2, 1, 0, 1, "\"Still wrong\"", "null", 0), "11/08/2026 07:10:00");
            Rem(r, Device, RemError, RemResult(RemError, Device, 3, 1, 0, 0, "\"Missing\"", "\"Set-ItemProperty : Access denied\"", 0), "11/08/2026 07:20:00");
            Rem(r, Device, RemBroken, "{\"PolicyId\":\"x\",\"RemediationStatus\":", "not a date");
            Rem(r, Device, RemExecOnly, null, "11/08/2026 07:30:00");
            r.Sz(Ime + @"\SideCarPolicies\Scripts\Reports\" + Device, "LastFullReportTimeUTC", "11/08/2026 07:00:00");
            return r;
        }

        static ImeItem Find(List<ImeItem> l, string kind, string id)
        {
            foreach (ImeItem i in l) if (i.Kind == kind && string.Equals(i.Id, id, StringComparison.OrdinalIgnoreCase)) return i;
            return null;
        }

        static int CountKind(List<ImeItem> l, string kind)
        {
            int n = 0;
            foreach (ImeItem i in l) if (i.Kind == kind) n++;
            return n;
        }

        static bool Has(ImeItem i, string text)
        {
            return i != null && i.Detail != null && i.Detail.Contains(text);
        }

        public static void Run()
        {
            Win32Apps();
            Scripts();
            Remediations();
            Robustness();
            Json();
            Codes();
            Times();
            LogNames();
            Snapshot();
        }

        static void Win32Apps()
        {
            List<ImeItem> l = ImeCollector.Collect(Sample());
            Check(CountKind(l, "Win32 app") == 10, "ten Win32 apps (" + CountKind(l, "Win32 app") + ")");
            Check(Find(l, "Win32 app", "not-an-app") == null, "non-GUID key skipped");

            ImeItem chrome = Find(l, "Win32 app", AppChrome);
            Check(chrome != null && chrome.Status == "Installed" && !chrome.Failed, "installed app");
            Check(chrome != null && chrome.User == "System", "all-zero user ID is System");
            Check(chrome != null && chrome.RegistryPath.EndsWith(AppChrome + "_3"), "newest revision used");
            Check(chrome != null && chrome.Time.HasValue && chrome.Time.Value == new DateTime(2026, 11, 7, 8, 15, 0, DateTimeKind.Utc) && chrome.Time.Value.Kind == DateTimeKind.Utc, "LastUpdatedTimeUtc read as UTC");
            Check(chrome != null && chrome.ErrorCode == null, "no error code when 0");
            Check(chrome != null && chrome.Assignment == "Required", "intent 3 is Required");
            Check(Has(chrome, "revision 3") && Has(chrome, "also in the registry: revision 1"), "revisions in detail");
            Check(Has(chrome, "Compliance state: Installed (1)") && Has(chrome, "Enforcement state: Success (1000)"), "parsed JSON fields in detail");
            Check(Has(chrome, "Install context: System (2)") && Has(chrome, "Target type: Device (2)"), "context and target type in detail");

            ImeItem vpn = Find(l, "Win32 app", AppVpn);
            Check(vpn != null && vpn.Failed && vpn.Status == "Detection failed", "0x87D1041C is Detection failed (" + (vpn == null ? "" : vpn.Status) + ")");
            Check(vpn != null && vpn.ErrorCode != null && vpn.ErrorCode.StartsWith("0x87D1041C: The application was not detected"), "hex error code with meaning");
            Check(Has(vpn, "Hint: The installer finished, but the detection rule"), "hint for 0x87D1041C");
            Check(Has(vpn, "Retry schedule (GRS): last attempt 2026-11-08 07:00:05 UTC") && Has(vpn, "next attempt after about 2026-11-09 07:00:05 UTC"), "GRS time read");
            Check(Has(vpn, @"GRS\5Nhyy9sV9nLHHCfYAgLksr+hQcuj2kFV2IGbNYi48u4="), "GRS hash shown");
            Check(Has(vpn, "Status service report") && Has(vpn, "Status = NotInstalled"), "status service report merged");

            ImeItem tmo = Find(l, "Win32 app", AppTimeout);
            Check(tmo != null && tmo.Failed && tmo.Status == "Install failed", "0x87D300C9 is Install failed");
            Check(tmo != null && tmo.User == Anna, "user object ID kept");
            Check(tmo != null && tmo.ErrorCode == "0x87D300C9: The unmonitored process is in progress, however it may timeout.", "0x87D300C9 meaning");
            Check(Has(tmo, "user with Entra object ID " + Anna), "user target in detail");
            Check(tmo != null && tmo.Time.HasValue && tmo.Time.Value == new DateTime(2026, 11, 8, 6, 30, 0, DateTimeKind.Utc), "ISO time read");

            ImeItem reb = Find(l, "Win32 app", AppReboot);
            Check(reb != null && reb.Status == "Installed, reboot pending" && !reb.Failed, "reboot pending");
            Check(Has(reb, "Meaning: The app has been installed but is not usable until the device has rebooted."), "enforcement meaning");

            ImeItem na = Find(l, "Win32 app", AppNotApplicable);
            Check(na != null && na.Status == "Not applicable" && !na.Failed, "requirements not met");
            Check(Has(na, "Applicability: Registry requirement rule not met (1007)"), "applicability text");

            ImeItem broken = Find(l, "Win32 app", AppBroken);
            Check(broken != null && broken.Status == "Not installed" && !broken.Failed, "partial JSON still read (" + (broken == null ? "" : broken.Status) + ")");
            Check(Has(broken, "the JSON is incomplete or not valid") && Has(broken, "Raw: not json at all"), "malformed JSON reported");
            Check(Has(broken, "garbage (not a recognised date)"), "bad date kept as text");
            Check(broken != null && !broken.Time.HasValue, "bad date gives no time");

            ImeItem retry = Find(l, "Win32 app", AppRetry);
            Check(retry != null && retry.Failed && retry.Status == "Waiting for retry", "5999 is Waiting for retry");
            Check(retry != null && retry.ErrorCode == "0x00000652 (1618): Another installation is already in progress.", "MSI exit code (" + (retry == null ? "" : retry.ErrorCode) + ")");

            ImeItem msi = Find(l, "Win32 app", AppMsi);
            Check(msi != null && msi.Failed && msi.Status == "Install failed", "MSI failure");
            Check(msi != null && msi.ErrorCode == "0x80070643: Fatal error during installation (Windows Installer 1603).", "error code given as hex text");

            ImeItem un = Find(l, "Win32 app", AppUninstall);
            Check(un != null && un.Status == "Not installed" && !un.Failed && un.Assignment == "Uninstall", "uninstall assignment");

            ImeItem rep = Find(l, "Win32 app", AppReportOnly);
            Check(rep != null && rep.Status == "Installed" && !rep.Failed && rep.User == "System", "status service report only");
            Check(Has(rep, "no state for this app under Win32Apps"), "report-only note");

            Check(l.Count > 0 && l[0].Kind == "Win32 app" && l[0].Failed, "failures sorted first");
        }

        static void Scripts()
        {
            List<ImeItem> l = ImeCollector.Collect(Sample());
            Check(CountKind(l, "Platform script") == 3, "three platform scripts");

            ImeItem ok = Find(l, "Platform script", ScriptOk);
            Check(ok != null && ok.Status == "Succeeded" && !ok.Failed && ok.User == "System", "device script succeeded");
            Check(ok != null && ok.Time.HasValue && ok.Time.Value == new DateTime(2026, 11, 7, 22, 10, 41, DateTimeKind.Utc), "script time");
            Check(Has(ok, "Output:") && Has(ok, "    Configured OneDrive") && Has(ok, "    Done"), "ExecutionMsg shown as output");
            Check(Has(ok, "Runs (DownloadCount): 1"), "run count");

            ImeItem bad = Find(l, "Platform script", ScriptBad);
            Check(bad != null && bad.Status == "Failed" && bad.Failed && bad.User == Anna, "user script failed");
            Check(bad != null && bad.ErrorCode == "0x00000001 (1)", "script error code (" + (bad == null ? "" : bad.ErrorCode) + ")");
            Check(Has(bad, @"Access to the path 'C:\Windows\x' is denied."), "output of cut-off ResultDetails");
            Check(Has(bad, "next three check-ins"), "retry note");

            ImeItem pend = Find(l, "Platform script", ScriptPending);
            Check(pend != null && pend.Status == "Pending" && !pend.Failed, "script without result is pending");
        }

        static void Remediations()
        {
            List<ImeItem> l = ImeCollector.Collect(Sample());
            Check(CountKind(l, "Remediation") == 6, "six remediations");

            ImeItem fix = Find(l, "Remediation", RemFixed);
            Check(fix != null && fix.Status == "Issue fixed" && !fix.Failed && fix.User == "System", "issue found and fixed");
            Check(fix != null && fix.Time.HasValue && fix.Time.Value == new DateTime(2026, 11, 8, 6, 55, 46, DateTimeKind.Utc), "LastExecution time");
            Check(Has(fix, "Detection: exit code 1 (issue found)") && Has(fix, "Detection after remediation: exit code 0 (no issue)"), "exit codes in detail");
            Check(Has(fix, "Detection output: Two extra admins found"), "detection output in detail");
            Check(Has(fix, "Remediation status: Issue fixed (1)") && Has(fix, "First detection exit code: 1"), "parsed Info fields");
            Check(Has(fix, "Last full report: 2026-11-08 07:00:00 UTC"), "last full report time");

            ImeItem none = Find(l, "Remediation", RemNoIssue);
            Check(none != null && none.Status == "No issue" && !none.Failed, "no issue");

            ImeItem rec = Find(l, "Remediation", RemRecurred);
            Check(rec != null && rec.Status == "Issue recurred" && rec.Failed && rec.User == Anna, "issue recurred");

            ImeItem err = Find(l, "Remediation", RemError);
            Check(err != null && err.Status == "Remediation failed" && err.Failed, "remediation script error");
            Check(Has(err, "Remediation error: Set-ItemProperty : Access denied"), "remediation error text");

            ImeItem broken = Find(l, "Remediation", RemBroken);
            Check(broken != null && broken.Status == "Unknown" && !broken.Failed && Has(broken, "the JSON is incomplete"), "malformed remediation result");
            Check(Has(broken, "not a date (not a recognised date)"), "bad LastExecution kept as text");

            ImeItem exec = Find(l, "Remediation", RemExecOnly);
            Check(exec != null && exec.Status == "No result yet" && exec.Time.HasValue && exec.RegistryPath.Contains(@"\Execution\"), "execution record without report");

            bool f;
            Check(ImeCollector.RemediationStatus(1, 0, 0, null, false, 0, out f) == "Issue found" && !f, "fallback: issue found");
            Check(ImeCollector.RemediationStatus(1, 1, 0, null, false, 0, out f) == "Remediation failed" && f, "fallback: remediation exit 1");
            Check(ImeCollector.RemediationStatus(1, 0, 1, null, false, 0, out f) == "Issue recurred" && f, "fallback: last detection 1");
            Check(ImeCollector.RemediationStatus(0, 0, 0, 99, false, 0, out f) == "No issue" && !f, "unknown status number with exit 0");
            Check(ImeCollector.RemediationStatus(0, 0, 0, 4, false, -2016345060, out f) == "Failed" && f, "error code wins");
        }

        static void Robustness()
        {
            Check(ImeCollector.Collect(null).Count == 0, "null registry");
            Check(ImeCollector.Collect(new ImeFakeRegistry()).Count == 0, "empty registry");

            ImeFakeRegistry t = Sample();
            t.Throw = true;
            List<ImeItem> thrown = null;
            try { thrown = ImeCollector.Collect(t); } catch (Exception) { }
            Check(thrown != null && thrown.Count == 0, "registry that throws");

            ImeFakeRegistry d = Sample();
            d.Deny(Ime + @"\Policies");
            List<ImeItem> l = ImeCollector.Collect(d);
            Check(CountKind(l, "Platform script") == 0 && CountKind(l, "Win32 app") == 10, "denied key skipped, rest read");
            ImeItem agent = Find(l, "IME", "IntuneManagementExtension");
            Check(agent != null && agent.Status == "Access denied" && Has(agent, @"IntuneManagementExtension\Policies"), "access denied item");
            Check(l.Count > 0 && l[0].Kind == "IME", "agent item first");

            ImeFakeRegistry big = new ImeFakeRegistry();
            for (int i = 0; i < 250; i++)
                App(big, Device, Guid.NewGuid().ToString() + "_1", Cs(0, 1, 2, "0", 2, 2), Es(1000, "0"), null);
            List<ImeItem> capped = ImeCollector.Collect(big, 100);
            Check(CountKind(capped, "Win32 app") == 100, "cap on items per kind");
            ImeItem limit = Find(capped, "IME", "Limit");
            Check(limit != null && limit.Detail.Contains("first 100 Win32 apps"), "cap noted");
            Check(CountKind(ImeCollector.Collect(big), "Win32 app") == 250, "default cap is large");

            ImeFakeRegistry many = new ImeFakeRegistry();
            for (int i = 0; i < 800; i++)
                App(many, i % 2 == 0 ? Device : Anna, Guid.NewGuid().ToString() + "_" + (i % 5), Cs(0, i % 3 == 0 ? 2 : 1, 2, i % 3 == 0 ? "-2016345060" : "0", 2, 2), Es(i % 3 == 0 ? 5000 : 1000, i % 3 == 0 ? "-2016345060" : "0"), "11/08/2026 05:00:00");
            System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
            List<ImeItem> ml = ImeCollector.Collect(many);
            sw.Stop();
            Check(CountKind(ml, "Win32 app") == 800 && sw.ElapsedMilliseconds < 10000, "800 apps read in " + sw.ElapsedMilliseconds + " ms");

            ImeFakeRegistry odd = new ImeFakeRegistry();
            App(odd, Device, AppChrome + "_1", "[1,2,3]", "{\"EnforcementState\":\"1000\",\"ErrorCode\":1.5e300}", null);
            App(odd, Device, AppVpn + "_1", Cs(0, 7, 9, "0", 5, 9), Es(4242, "0"), null);
            App(odd, Device, AppTimeout + "_99999999999", null, null, null);
            App(odd, "S-1-5-21-1-2-3-1001", AppMsi, Cs(0, 1, 2, "0", 1, 1), null, null);
            App(odd, "{" + Device + "}", AppReboot + "_1", "{\"ComplianceState\":" + new string('[', 5000), null, null);
            App(odd, Device, AppRetry + "_1", Cs(0, 1, 2, "0", 2, 2), "{\"EnforcementState\":1000,\"x\":\"" + new string('a', 100000) + "\"}", null);
            List<ImeItem> ol = null;
            try { ol = ImeCollector.Collect(odd); } catch (Exception) { }
            Check(ol != null, "odd data does not throw");
            ImeItem a = Find(ol ?? new List<ImeItem>(), "Win32 app", AppChrome);
            Check(a != null && a.Status == "Installed", "string number and array JSON tolerated (" + (a == null ? "" : a.Status) + ")");
            ImeItem v = Find(ol ?? new List<ImeItem>(), "Win32 app", AppVpn);
            Check(v != null && v.Status == "Unknown" && Has(v, "unknown value 7") && Has(v, "unknown value 4242"), "unknown states shown as numbers");
            ImeItem s = Find(ol ?? new List<ImeItem>(), "Win32 app", AppMsi);
            Check(s != null && s.User == "S-1-5-21-1-2-3-1001" && s.Status == "Installed", "SID user key and key without revision");
            Check(Find(ol ?? new List<ImeItem>(), "Win32 app", AppTimeout) == null, "revision that is too long is skipped");
            ImeItem deep = Find(ol ?? new List<ImeItem>(), "Win32 app", AppReboot);
            Check(deep != null && deep.User == "System", "deep nesting tolerated, braced device ID");
            ImeItem huge = Find(ol ?? new List<ImeItem>(), "Win32 app", AppRetry);
            Check(huge != null && huge.Detail.Length <= 16100, "long detail capped");
        }

        static void Json()
        {
            bool ok;
            Dictionary<string, object> d = ImeJson.Parse("{\"a\":1,\"B\":\"x\\u0041\\n\",\"c\":[true,false,null,-2.5e1],\"d\":{\"e\":9007199254740993}}", out ok) as Dictionary<string, object>;
            Check(ok && d != null && (long)d["A"] == 1 && (string)d["b"] == "xA\n", "objects, case-insensitive keys, escapes");
            List<object> c = d == null ? null : d["c"] as List<object>;
            Check(c != null && c.Count == 4 && (bool)c[0] && !(bool)c[1] && c[2] == null && (double)c[3] == -25.0, "arrays and literals");
            Check(d != null && ImeJson.Long(ImeJson.Get(d["d"] as Dictionary<string, object>, "e")) == 9007199254740993L, "large integer kept exact");

            object partial = ImeJson.Parse("{\"a\":1,\"b\":{\"c\":2,\"d\":", out ok);
            Dictionary<string, object> p = partial as Dictionary<string, object>;
            Check(!ok && p != null && (long)p["a"] == 1 && p.ContainsKey("b"), "partial JSON keeps what was read");

            string[] bad = { null, "", "   ", "{", "}", "[", "{\"a\"", "{\"a\":}", "{\"a\":1,}", "\"open", "nul", "-", "1e", "{\"a\":\"\\u12\"}", "\u0000", new string('{', 10000), new string('[', 10000) + new string(']', 10000), "{\"a\":1} trailing" };
            bool threw = false;
            foreach (string s in bad)
            {
                try { ImeJson.Parse(s, out ok); }
                catch (Exception) { threw = true; }
            }
            Check(!threw, "malformed JSON never throws");
            ImeJson.Parse("{\"a\":1} trailing", out ok);
            Check(!ok, "trailing text is not complete");
            ImeJson.Parse("  [1, 2]  ", out ok);
            Check(ok, "whitespace around a value is complete");

            int end;
            object v = ImeJson.Parse("x = [{\"Id\":\"1\"}] tail", 4, true, out end, out ok);
            Check(ok && v is List<object> && end == 16, "parse from offset");
            ImeJson.Parse("[{\"Name\":\"cut\r\nnext line", 0, true, out end, out ok);
            Check(!ok && end < 15, "strict mode stops at a line break");

            Check(ImeJson.Long("0x87D1041C") == 0x87D1041CL && ImeJson.Long(-2016345060L) == -2016345060L && ImeJson.Long(2.0) == 2 && ImeJson.Long(2.5) == null && ImeJson.Long(true) == null, "number conversion");
            Check(ImeJson.Text(ImeJson.Parse("{\"a\":[1,\"b\"]}")) == "{\"a\":[1,\"b\"]}", "compact text of nested values");
        }

        static void Codes()
        {
            Check(ImeCodes.Format(0) == null, "0 has no code");
            Check(ImeCodes.Format(-2016345060) == ImeCodes.Format(0x87D1041CL), "signed and unsigned give the same code");
            Check(ImeCodes.Format(0x87D30065L) == "0x87D30065: Failed to retrieve content information.", "0x87D30065");
            Check(ImeCodes.Format(0x87D30067L) == "0x87D30067: Error unzipping downloaded content.", "0x87D30067");
            Check(ImeCodes.Format(1603) == "0x00000643 (1603): A fatal error occurred during installation.", "MSI 1603");
            Check(ImeCodes.Format(0x80070652L) == "0x80070652: Another installation is already in progress.", "HRESULT of MSI 1618");
            Check(ImeCodes.Format(0x12345678L) == "0x12345678", "unknown code has no meaning");
            Check(ImeCodes.Format(long.MaxValue) == long.MaxValue.ToString(), "out of range code");
            Check(ImeCodes.IsSuccess(3010) && ImeCodes.IsSuccess(1641) && ImeCodes.IsSuccess(0x80070BC2L) && !ImeCodes.IsSuccess(1603), "success codes");
            Check(ImeCodes.Parse(" 0x10 ") == 16 && ImeCodes.Parse("-1") == -1 && ImeCodes.Parse("x") == null && ImeCodes.Parse("0xZZ") == null, "code parsing");

            bool f;
            Check(ImeCollector.AppStatus(0, 2, 2, 5003, 0, out f) == "Download failed" && f, "download failed");
            Check(ImeCollector.AppStatus(0, 2, 2, 6001, 0, out f) == "Dependency failed" && f, "dependency failed");
            Check(ImeCollector.AppStatus(0, 2, 2, 6002, 0, out f) == "Waiting for reboot" && !f, "blocked by reboot");
            Check(ImeCollector.AppStatus(0, 2, 2, 2000, 0, out f) == "In progress" && !f, "in progress");
            Check(ImeCollector.AppStatus(0, 1, 2, 1000, 3010, out f) == "Installed" && !f, "3010 is not a failure");
            Check(ImeCollector.AppStatus(0, 1, 1, 5000, 1603, out f) == "Uninstall failed" && f, "uninstall failed");
            Check(ImeCollector.AppStatus(null, null, null, 1000, 0, out f) == "Installed" && !f, "enforcement only");
            Check(ImeCollector.AppStatus(null, null, null, null, 0, out f) == "Unknown" && !f, "nothing known");
            Check(ImeCollector.AppStatus(1010, 2, 2, 5000, 1, out f) == "Not applicable" && !f, "assignment filter not met");
            Check(ImeCollector.ScriptStatus("Success", 0, out f) == "Succeeded" && !f, "script success");
            Check(ImeCollector.ScriptStatus("Success", 5, out f) == "Failed" && f, "script success with error code");
            Check(ImeCollector.ScriptStatus("TimedOut", 0, out f) == "Timed out" && !f, "other script result kept");
        }

        static void Times()
        {
            DateTime want = new DateTime(2026, 10, 1, 2, 38, 27, DateTimeKind.Utc);
            Check(ImeTime.Parse("10/01/2026 02:38:27") == want, "US time");
            Check(ImeTime.Parse("10/1/2026 2:38:27 AM") == want, "US time with AM");
            Check(ImeTime.Parse("2026-10-01T02:38:27Z") == want, "ISO UTC");
            Check(ImeTime.Parse("2026-10-01T04:38:27+02:00") == want, "ISO with offset");
            Check(ImeTime.Parse("2026-10-01 02:38:27") == want, "ISO without zone is UTC");
            Check(ImeTime.Parse("01.10.2026 02:38:27") == want, "dotted day first");
            Check(ImeTime.Parse("25/10/2026 02:38:27") == new DateTime(2026, 10, 25, 2, 38, 27, DateTimeKind.Utc), "day first when month first is impossible");
            Check(ImeTime.Parse(want.ToFileTimeUtc().ToString()) == want, "file time number");
            Check(ImeTime.Parse(want.Ticks.ToString()) == want, "ticks number");
            Check(ImeTime.Parse("1790822307") == want, "Unix seconds");
            Check(ImeTime.Parse(null) == null && ImeTime.Parse("") == null && ImeTime.Parse("soon") == null && ImeTime.Parse("1/1/0001 00:00:00") == null && ImeTime.Parse("42") == null, "not dates");
        }

        static string LogLine(string text, string component)
        {
            return "<![LOG[" + text + "]LOG]!><time=\"07:06:13.1234567\" date=\"11-8-2026\" component=\"" + component + "\" context=\"\" type=\"1\" thread=\"14\" file=\"\">";
        }

        static void LogNames()
        {
            StringBuilder b = new StringBuilder();
            b.Append(LogLine("[Win32App] ..................... Processing user session 1, userId: " + Anna + ", userSID: S-1-12-1-1-2-3-4 .....................", "IntuneManagementExtension")).Append("\r\n");
            b.Append(LogLine("Get policies = [{\"Id\":\"" + AppChrome + "\",\"Name\":\"Google Chrome\",\"Version\":3,\"Intent\":3,\"DetectionRule\":\"[{\\\"DetectionType\\\":2,\\\"DetectionText\\\":\\\"{\\\\\\\"Path\\\\\\\":\\\\\\\"C:\\\\\\\\\\\\\\\\Program Files\\\\\\\"}\\\"}]\",\"InstallCommandLine\":\"setup.exe /S\"},"
                + "{\"Id\":\"" + AppVpn + "\",\"Name\":\"Cisco Secure Client (x64)\",\"Version\":2,\"Intent\":3}]", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("[Win32App][ReportingManager] Sending results to service. session RequestPayload: [{\"AppId\":\"" + AppNotApplicable + "\",\"ApplicationName\":\"Visio Viewer\",\"ComplianceStateMessage\":{\"Applicability\":1007}}]", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("[Win32App] Content cache miss for app (id = " + AppReboot + ", name = Scribe Desktop Capture)", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("[StatusService] Downloading app (id = " + AppMsi + ", name Notepad++ (64-bit)) via DO, bytes 0/1024", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("[HS] Get policies = [{\"AccountId\":\"x\",\"PolicyId\":\"" + RemFixed + "\",\"PolicyType\":6,\"PolicyBody\":\"PCMN\"}]", "HealthScripts")).Append("\r\n");
            b.Append(LogLine("Get policies = [{\"Id\":\"" + AppTimeout + "\",\"Name\":\"Truncated App\",\"Version\":1},{\"Id\":\"" + AppRetry + "\",\"Name\":\"Cut o", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("Get policies = [{\"Id\":\"" + AppChrome + "\",\"Name\":\"Google Chrome Enterprise\"}]", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("Get policies = [{\"Id\":\"not-a-guid\",\"Name\":\"Ignored\"},{\"Id\":\"" + AppBroken + "\",\"Name\":\"\"}]", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("Get policies = garbage", "AppWorkload")).Append("\r\n");
            b.Append(LogLine("(id = " + AppUninstall + ", name never closed", "AppWorkload"));

            Dictionary<string, string> names = ImeLog.ParseNames(b.ToString());
            Check(names.ContainsKey(AppChrome) && names[AppChrome] == "Google Chrome Enterprise", "later line wins");
            Check(names.ContainsKey(AppVpn) && names[AppVpn] == "Cisco Secure Client (x64)", "second policy in array");
            Check(names.ContainsKey(AppNotApplicable) && names[AppNotApplicable] == "Visio Viewer", "name from reporting payload");
            Check(names.ContainsKey(AppReboot) && names[AppReboot] == "Scribe Desktop Capture", "content cache miss line");
            Check(names.ContainsKey(AppMsi) && names[AppMsi] == "Notepad++ (64-bit)", "downloading app line with parentheses");
            Check(names.ContainsKey(AppTimeout) && names[AppTimeout] == "Truncated App", "cut-off line keeps complete entries");
            Check(!names.ContainsKey(AppRetry), "cut-off name not used");
            Check(!names.ContainsKey(RemFixed), "remediation policy without a name not guessed");
            Check(!names.ContainsKey(AppBroken) && !names.ContainsKey("not-a-guid") && !names.ContainsKey(AppUninstall), "empty names, bad IDs and open lines skipped");

            List<ImeItem> items = ImeCollector.Collect(Sample());
            Find(items, "Win32 app", AppVpn).Name = "Kept";
            string dir = Path.Combine(Path.GetTempPath(), "pv-ime-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string log = Path.Combine(dir, "AppWorkload.log");
                File.WriteAllText(log, b.ToString(), new UTF8Encoding(true));
                int n;
                using (FileStream hold = new FileStream(log, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    n = ImeLog.FillNames(items, log);
                }
                Check(n == 5, "names filled from file (" + n + ")");
                Check(Find(items, "Win32 app", AppChrome).Name == "Google Chrome Enterprise" && Find(items, "Win32 app", AppChrome).DisplayName == "Google Chrome Enterprise", "Chrome named");
                Check(Find(items, "Win32 app", AppVpn).Name == "Kept", "existing name kept");
                Check(Find(items, "Win32 app", AppRetry).Name == null && Find(items, "Win32 app", AppRetry).DisplayName == AppRetry, "unnamed app shows its ID");

                string all = b.ToString();
                int last = all.LastIndexOf("<![LOG[Get policies = [{\"Id\":\"" + AppChrome, StringComparison.Ordinal);
                Dictionary<string, string> tail = ImeLog.ReadNames(log, Encoding.UTF8.GetByteCount(all.Substring(last - 2)));
                Check(tail.ContainsKey(AppChrome) && !tail.ContainsKey(AppReboot), "only the tail is read");

                string u16 = Path.Combine(dir, "IntuneManagementExtension.log");
                File.WriteAllText(u16, LogLine("Get policies = [{\"Id\":\"" + AppUninstall + "\",\"Name\":\"Old Toolbar\"}]", "IME"), new UnicodeEncoding(false, true));
                File.WriteAllText(Path.Combine(dir, "Other.log"), LogLine("Get policies = [{\"Id\":\"" + AppBroken + "\",\"Name\":\"Not read\"}]", "x"));
                List<ImeItem> fresh = ImeCollector.Collect(Sample());
                int m = ImeLog.FillNamesFromFolder(fresh, dir);
                Check(Find(fresh, "Win32 app", AppUninstall).Name == "Old Toolbar", "UTF-16 log in folder");
                Check(Find(fresh, "Win32 app", AppBroken).Name == null, "other log files ignored");
                Check(m == 7, "names filled from folder (" + m + ")");
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch (Exception) { }
            }

            Check(ImeLog.ReadNames(null).Count == 0 && ImeLog.ReadNames(Path.Combine(dir, "missing.log")).Count == 0 && ImeLog.ReadNames(Path.GetTempPath()).Count == 0, "missing file or folder path");
            Check(ImeLog.FillNames(null, "x") == 0 && ImeLog.FillNames(new List<ImeItem>(), (string)null) == 0 && ImeLog.FillNamesFromFolder(items, null) == 0, "null arguments");
            Check(ImeLog.ParseNames(null).Count == 0 && ImeLog.ParseNames("Get policies = [" + new string('[', 5000)).Count == 0, "bad text");
        }

        static void Snapshot()
        {
            Snapshot s = new Snapshot();
            s.Intune = ImeCollector.Collect(Sample());
            string path = Path.Combine(Path.GetTempPath(), "pv-ime-" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                s.Save(path);
                Snapshot back = PolicyVice.Snapshot.Load(path);
                ImeItem a = Find(back.Intune, "Win32 app", AppVpn);
                ImeItem b = Find(s.Intune, "Win32 app", AppVpn);
                Check(back.Intune.Count == s.Intune.Count && a != null && a.Status == b.Status && a.Detail == b.Detail && a.Time == b.Time && a.Assignment == b.Assignment, "items survive a snapshot");
            }
            finally
            {
                try { File.Delete(path); } catch (Exception) { }
            }
        }
    }
}
