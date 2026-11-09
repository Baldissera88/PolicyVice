namespace PolicyVice.Tests
{
    public static class EnrichTests
    {
        static void Check(bool ok, string what)
        {
            T.Check(ok, "enrich: " + what);
        }

        static PolicySetting Mdm(Snapshot s, string area, string name, string value)
        {
            PolicySetting p = new PolicySetting();
            p.Layer = Layers.Mdm;
            p.Scope = "Device";
            p.Area = area;
            p.Name = name;
            p.Value = value;
            p.FriendlyName = Txt.SplitCamel(name);
            p.Source = Sources.Intune;
            s.Settings.Add(p);
            return p;
        }

        static PolicySetting Gp(Snapshot s, string area, string name, string value, string gpo)
        {
            PolicySetting p = new PolicySetting();
            p.Layer = Layers.Registry;
            p.Scope = "Device";
            p.Area = area;
            p.Name = name;
            p.Value = value;
            p.Source = gpo == null ? Sources.Unmanaged : Sources.GroupPolicy;
            p.SourceDetail = gpo;
            s.Settings.Add(p);
            return p;
        }

        public static void Run()
        {
            CspCatalog csp = CspCatalog.Embedded();
            AdmxCatalog admx = new AdmxCatalog();
            admx.Load("WindowsUpdate",
                "<policyDefinitions><policies><policy name=\"AutoUpdateCfg\" class=\"Machine\" displayName=\"Configure Automatic Updates\" key=\"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" valueName=\"NoAutoUpdate\"><elements><enum id=\"AutoUpdateMode\" valueName=\"AUOptions\"/></elements></policy></policies></policyDefinitions>",
                null, false);
            admx.Load("TerminalServer",
                "<policyDefinitions><policies><policy name=\"TS_DISABLE_CONNECTIONS\" class=\"Machine\" displayName=\"Allow users to connect remotely by using Remote Desktop Services\" key=\"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" valueName=\"fDenyTSConnections\"/></policies></policyDefinitions>",
                null, false);

            Snapshot s = new Snapshot();
            s.MdmWinsOverGp = true;
            PolicySetting au = Mdm(s, "Update", "AllowAutoUpdate", "5");
            PolicySetting rt = Mdm(s, "Defender", "AllowRealtimeMonitoring", "1");
            PolicySetting ts = Mdm(s, "RemoteDesktopServices", "AllowUsersToConnectRemotely", "<enabled/>");
            PolicySetting dis = Mdm(s, "ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS_X", "<disabled/>");
            PolicySetting unknown = Mdm(s, "NoSuchArea", "NoSuchSetting", "1");
            PolicySetting gpAu = Gp(s, @"Microsoft\Windows\WindowsUpdate\AU", "AUOptions", "4", "WSUS - Clients");
            PolicySetting gpRt = Gp(s, @"Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "0", "Defender baseline");
            PolicySetting gpTs = Gp(s, @"Microsoft\Windows NT\Terminal Services", "fDenyTSConnections", "1", "Legacy - Workstations");
            PolicySetting gpOther = Gp(s, @"Microsoft\Windows\Personalization", "NoLockScreenCamera", "1", "Baseline");
            PolicySetting tattoo = Gp(s, @"Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "1", null);
            tattoo.Name = "DisableRealtimeMonitoring";

            Enricher.Apply(s, csp, admx);

            Check(au.ValueMeaning == "Turn off automatic updates", "Update meaning: " + au.ValueMeaning);
            Check(au.DisplayValue == "5 (Turn off automatic updates)", "display value");
            Check(au.FriendlyName == "Allow Auto Update", "non-ADMX keeps its own name");
            Check(au.GroupPolicyName == "Configure Automatic Updates", "GP counterpart name: " + au.GroupPolicyName);
            Check(!string.IsNullOrEmpty(au.GroupPolicyPath) && !string.IsNullOrEmpty(au.Description), "GP path and description");
            Check(rt.ValueMeaning == "Allowed", "Defender meaning: " + rt.ValueMeaning);
            Check(ts.ValueMeaning == "Enabled" && dis.ValueMeaning == "Disabled", "ADMX enabled and disabled");
            Check(ts.FriendlyName != null && ts.FriendlyName.StartsWith("Allow users to connect remotely"), "ADMX-backed gets GP name: " + ts.FriendlyName);
            Check(unknown.ValueMeaning == null && unknown.FriendlyName == "No Such Setting", "unknown setting untouched");

            Check(au.Has(FindingKinds.Conflict) && gpAu.Has(FindingKinds.Conflict), "conflict through the ADMX policy");
            Check(au.Findings.Count == 1 && au.Findings[0].Message.Contains("WSUS - Clients") && au.Findings[0].Message.Contains("blocks"), "MDM side message");
            Check(gpAu.Findings[0].Message.Contains("Update/AllowAutoUpdate = 5 (Turn off automatic updates)"), "GP side message");
            Check(rt.Has(FindingKinds.Conflict) && gpRt.Has(FindingKinds.Conflict), "conflict through the documented registry value");
            Check(ts.Has(FindingKinds.Conflict) && gpTs.Has(FindingKinds.Conflict), "conflict for an ADMX-backed setting in a regular area");
            Check(!gpOther.Has(FindingKinds.Conflict), "no conflict without an MDM counterpart");
            Check(!tattoo.Has(FindingKinds.Conflict), "unmanaged values are not conflicts");

            Snapshot u = new Snapshot();
            PolicySetting um = Mdm(u, "Defender", "AllowRealtimeMonitoring", "1");
            um.Scope = "User";
            um.UserSid = "S-1-12-1-1";
            Gp(u, @"Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "0", "Defender baseline");
            Enricher.Apply(u, csp, admx);
            Check(!um.Has(FindingKinds.Conflict), "no conflict across scopes");

            Enricher.Apply(null, csp, admx);
            Snapshot empty = new Snapshot();
            Enricher.Apply(empty, null, null);
            Check(empty.Settings.Count == 0, "null inputs tolerated");

            Check(Enricher.Short("Not allowed. Turns off the real-time monitoring service.") == "Not allowed", "short meaning");
            Check(Enricher.Short(new string('x', 100)).Length == 70, "long meaning cut");
        }
    }
}
