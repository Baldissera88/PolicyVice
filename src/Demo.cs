namespace PolicyVice
{
    using System;
    using System.Collections.Generic;

    // In-memory sources, used by the demo mode (PolicyVice.exe --demo) to show the app without touching the device.
    public sealed class MemoryRegistry : IRegSource
    {
        readonly Dictionary<string, Dictionary<string, RegValue>> keys = new Dictionary<string, Dictionary<string, RegValue>>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> denied = new List<string>();

        public List<string> Denied
        {
            get { return denied; }
        }

        public void Set(string path, string name, string kind, string data)
        {
            Ensure(path)[name] = new RegValue(kind, data);
        }

        public void Dword(string path, string name, int data)
        {
            Set(path, name, "REG_DWORD", data.ToString());
        }

        public void Sz(string path, string name, string data)
        {
            Set(path, name, "REG_SZ", data);
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

        public string[] SubKeys(string path)
        {
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
            Dictionary<string, RegValue> v;
            if (!keys.TryGetValue(path, out v)) return new string[0];
            return new List<string>(v.Keys).ToArray();
        }

        public RegValue Get(string path, string name)
        {
            Dictionary<string, RegValue> v;
            RegValue r;
            return keys.TryGetValue(path, out v) && v.TryGetValue(name, out r) ? r : null;
        }
    }

    public sealed class MemoryRsop : IRsopSource
    {
        public readonly List<RsopValue> Values = new List<RsopValue>();

        public List<RsopValue> ComputerValues(out string note)
        {
            note = null;
            return Values;
        }

        public void Add(string key, string name, string data, string gpo, int prec)
        {
            RsopValue r = new RsopValue();
            r.Key = key;
            r.ValueName = name;
            r.Data = data;
            r.Kind = "REG_DWORD";
            r.GpoName = gpo;
            r.GpoId = gpo;
            r.Precedence = prec;
            Values.Add(r);
        }
    }

    public sealed class MemoryEvents : IEventSource
    {
        public readonly List<EventItem> Items = new List<EventItem>();

        public List<EventItem> Read(string channel, DateTime since, bool errorsOnly)
        {
            return Items;
        }

        public void Add(DateTime t, int id, string level, string message)
        {
            EventItem e = new EventItem();
            e.Time = t;
            e.Id = id;
            e.Level = level;
            e.Message = message;
            Items.Add(e);
        }
    }

    public static class Demo
    {
        const string Intune = "6F1C2D3A-8E4B-4C2F-9A1D-3B5E7C9D0F12";
        const string Pm = @"HKLM\SOFTWARE\Microsoft\PolicyManager";
        const string Sid = "S-1-12-1-2754031901-1290781185-3107561857-2981237123";

        public static Snapshot Build(int variant)
        {
            MemoryRegistry r = new MemoryRegistry();
            string e = @"HKLM\SOFTWARE\Microsoft\Enrollments\" + Intune;
            r.Sz(e, "ProviderID", "MS DM Server");
            r.Sz(e, "UPN", "anna.hansen@contoso.com");
            r.Dword(e, "EnrollmentType", 6);
            r.Dword(e, "EnrollmentState", 1);
            r.Sz(e, "DiscoveryServiceFullURL", "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc");

            string dev = Pm + @"\current\device";
            string prov = Pm + @"\providers\" + Intune + @"\default\Device";
            Mdm(r, dev, prov, "Update", "AllowAutoUpdate", 1);
            Mdm(r, dev, prov, "Update", "DeferQualityUpdatesPeriodInDays", 3);
            Mdm(r, dev, prov, "Update", "DeferFeatureUpdatesPeriodInDays", 30);
            Mdm(r, dev, prov, "Update", "ActiveHoursStart", 7);
            Mdm(r, dev, prov, "Update", "ActiveHoursEnd", 18);
            Mdm(r, dev, prov, "Update", "ConfigureDeadlineForQualityUpdates", 2);
            Mdm(r, dev, prov, "Defender", "AllowRealtimeMonitoring", 1);
            Mdm(r, dev, prov, "Defender", "AllowCloudProtection", 1);
            Mdm(r, dev, prov, "Defender", "CloudBlockLevel", 2);
            Mdm(r, dev, prov, "Defender", "PUAProtection", 1);
            Mdm(r, dev, prov, "DeviceLock", "DevicePasswordEnabled", 0);
            Mdm(r, dev, prov, "DeviceLock", "MinDevicePasswordLength", 8);
            Mdm(r, dev, prov, "Experience", "AllowCortana", 0);
            Mdm(r, dev, prov, "Experience", "DoNotShowFeedbackNotifications", 1);
            Mdm(r, dev, prov, "Privacy", "LetAppsAccessCamera", 0);
            Mdm(r, dev, prov, "Browser", "AllowSmartScreen", 1);
            Mdm(r, dev, prov, "Bluetooth", "AllowDiscoverableMode", 0);
            Mdm(r, dev, prov, "Connectivity", "AllowUSBConnection", 1);
            Mdm(r, dev, prov, "LocalPoliciesSecurityOptions", "InteractiveLogon_DoNotDisplayLastSignedIn", 1);
            Mdm(r, dev, prov, "WindowsLogon", "HideFastUserSwitching", 1);
            r.Sz(dev + @"\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS", "<enabled/>");
            r.Sz(dev + @"\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS_WinningProvider", Intune);
            r.Sz(prov + @"\ADMX_TerminalServer", "TS_DISABLE_CONNECTIONS", "<enabled/>");
            string od = "OneDriveNGSCv2~Policy~OneDriveNGSC";
            r.Sz(dev + "\\" + od, "KFMSilentOptIn", "<enabled/><data id=\"KFMSilentOptInBox\" value=\"8a1b3c2d-contoso-tenant\"/>");
            r.Sz(prov + "\\" + od, "KFMSilentOptIn", "<enabled/>");
            r.Sz(dev + "\\" + od, "FilesOnDemandEnabled", "<enabled/>");
            r.Sz(prov + "\\" + od, "FilesOnDemandEnabled", "<enabled/>");
            if (variant == 0)
            {
                r.Sz(dev + "\\" + od, "SilentAccountConfig", "<enabled/>");
                r.Sz(prov + "\\" + od, "SilentAccountConfig", "<enabled/>");
            }
            r.Dword(dev + @"\Defender", "EnableNetworkProtection", 1);
            Mdm(r, dev, prov, "ControlPolicyConflict", "MDMWinsOverGP", 1);
            r.Dword(Pm + @"\current\" + Sid + @"\Start", "HideRecentlyAddedApps", 1);
            r.Dword(Pm + @"\providers\" + Intune + @"\default\" + Sid + @"\Start", "HideRecentlyAddedApps", 1);
            r.Sz(Pm + @"\AdmxInstalled\" + Intune + @"\OneDriveNGSCv2\Policy", "OneDriveAdmx", "1");

            string pol = @"HKLM\SOFTWARE\Policies\Microsoft";
            r.Dword(pol + @"\Windows NT\Terminal Services", "fDenyTSConnections", 0);
            r.Dword(pol + @"\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0);
            r.Dword(pol + @"\Windows\WindowsUpdate\AU", "AUOptions", 4);
            r.Sz(pol + @"\Windows\WindowsUpdate", "WUServer", "https://wsus.contoso.local:8531");
            r.Sz(pol + @"\OneDrive", "KFMSilentOptIn", "8a1b3c2d-contoso-tenant");
            r.Dword(pol + @"\OneDrive", "FilesOnDemandEnabled", 1);
            if (variant == 0) r.Dword(pol + @"\OneDrive", "SilentAccountConfig", 1);
            r.Dword(pol + @"\Windows\System", "EnableSmartScreen", 1);
            r.Dword(pol + @"\Edge", "SmartScreenEnabled", 1);
            r.Dword(pol + @"\FVE", "EncryptionMethodWithXtsOs", 7);
            r.Dword(pol + @"\Windows\Personalization", "NoLockScreenCamera", variant == 0 ? 1 : 0);
            r.Dword(pol + @"\Legacy\Tools", "DisableTaskMgr", 1);
            r.Sz(@"HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Common", "QMEnable", "0");

            MemoryRsop gp = new MemoryRsop();
            gp.Add(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections", "0", "Baseline - Remote Desktop", 1);
            gp.Add(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections", "1", "Legacy - Workstations", 2);
            gp.Add(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "0", "WSUS - Clients", 1);
            gp.Add(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", "4", "WSUS - Clients", 1);
            gp.Add(@"Software\Policies\Microsoft\Windows\WindowsUpdate", "WUServer", "https://wsus.contoso.local:8531", "WSUS - Clients", 1);
            gp.Add(@"Software\Policies\Microsoft\Windows\System", "EnableSmartScreen", "1", "Baseline - Security", 1);
            gp.Add(@"Software\Policies\Microsoft\Edge", "SmartScreenEnabled", "1", "Edge - Baseline", 1);
            gp.Add(@"Software\Policies\Microsoft\FVE", "EncryptionMethodWithXtsOs", "7", "Baseline - BitLocker", 1);
            gp.Add(@"Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", "1", "Baseline - Security", 1);

            DateTime now = new DateTime(2026, 11, 8, 21, 40, 0);
            MemoryEvents ev = new MemoryEvents();
            ev.Add(now.AddHours(-2), 404, "Error", "MDM ConfigurationManager: Command failure status. Configuration Source ID: (" + Intune + "), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), Command Type: (CmdType_Add), CSP URI: (./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection), Result: (The data is invalid.).");
            ev.Add(now.AddHours(-2), 404, "Error", "MDM ConfigurationManager: Command failure status. Configuration Source ID: (" + Intune + "), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), Command Type: (CmdType_Add), CSP URI: (./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForQualityUpdates), Result: (The parameter is incorrect.).");
            ev.Add(now.AddHours(-26), 454, "Warning", "MDM PolicyManager: Set policy int, Policy: (AllowUSBConnection), Area: (Connectivity), EnrollmentID requesting merge: (" + Intune + "), Current User: (Device), Int: (0x1), Enrollment Type: (0x6), Scope: (0x0), Result:(0x80070032) The request is not supported.");

            AdmxCatalog c = new AdmxCatalog();
            c.Load("TerminalServer",
                "<policyDefinitions><policies><policy name=\"TS_DISABLE_CONNECTIONS\" class=\"Machine\" displayName=\"$(string.TS_DISABLE_CONNECTIONS)\" explainText=\"$(string.TS_DISABLE_CONNECTIONS_EXPLAIN)\" key=\"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" valueName=\"fDenyTSConnections\"/></policies></policyDefinitions>",
                "<policyDefinitionResources><resources><stringTable><string id=\"TS_DISABLE_CONNECTIONS\">Allow users to connect remotely by using Remote Desktop Services</string><string id=\"TS_DISABLE_CONNECTIONS_EXPLAIN\">This policy setting allows you to configure remote access to computers by using Remote Desktop Services.</string></stringTable></resources></policyDefinitionResources>",
                false);
            c.Load("WindowsUpdate",
                "<policyDefinitions><policies><policy name=\"AutoUpdateCfg\" class=\"Machine\" displayName=\"Configure Automatic Updates\" key=\"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" valueName=\"NoAutoUpdate\"><elements><enum id=\"AutoUpdateMode\" valueName=\"AUOptions\"/></elements></policy><policy name=\"CorpWuURL\" class=\"Machine\" displayName=\"Specify intranet Microsoft update service location\" key=\"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\"><elements><text id=\"CorpWUURL_Name\" valueName=\"WUServer\"/></elements></policy></policies></policyDefinitions>",
                null, false);
            c.Load("OneDrive",
                "<policyDefinitions><policies><policy name=\"KFMSilentOptIn\" class=\"Machine\" displayName=\"Silently move Windows known folders to OneDrive\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"><elements><text id=\"KFMSilentOptInBox\" valueName=\"KFMSilentOptIn\"/></elements></policy><policy name=\"FilesOnDemandEnabled\" class=\"Machine\" displayName=\"Use OneDrive Files On-Demand\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"FilesOnDemandEnabled\"/><policy name=\"SilentAccountConfig\" class=\"Machine\" displayName=\"Silently sign in users to the OneDrive sync app with their Windows credentials\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"SilentAccountConfig\"/></policies></policyDefinitions>",
                null, true);
            c.Load("Edge",
                "<policyDefinitions><policies><policy name=\"SmartScreenEnabled\" class=\"Both\" displayName=\"Configure Microsoft Defender SmartScreen\" key=\"Software\\Policies\\Microsoft\\Edge\" valueName=\"SmartScreenEnabled\"/></policies></policyDefinitions>",
                null, false);

            CollectOptions o = new CollectOptions();
            o.Computer = "CONTOSO-PC042";
            o.UserName = "CONTOSO\\anna.hansen";
            o.OsVersion = "Windows 11 Enterprise 25H2 (26200.7171)";
            o.Elevated = true;
            o.Version = Program.Version;
            o.CurrentUserSid = Sid;
            o.EventDays = 7;
            o.NowUtc = now.AddMinutes(variant).ToUniversalTime();
            return Collector.Collect(r, gp, ev, c, o);
        }

        static void Mdm(MemoryRegistry r, string dev, string prov, string area, string name, int value)
        {
            r.Dword(dev + "\\" + area, name, value);
            r.Dword(dev + "\\" + area, name + "_ProviderSet", 1);
            r.Sz(dev + "\\" + area, name + "_WinningProvider", Intune);
            r.Dword(prov + "\\" + area, name, value);
        }
    }
}
