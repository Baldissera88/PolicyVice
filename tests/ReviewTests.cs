namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;

    // Cases from the code review: ADMX-backed MDM settings outside ADMX_ areas, CurrentVersion\Policies,
    // failures of settings that were never applied, and the signed-in user when running as another account.
    public static class ReviewTests
    {
        const string Pm = @"HKLM\SOFTWARE\Microsoft\PolicyManager";
        const string Intune = "3A1B2C3D-0000-4000-8000-000000000001";
        const string Admin = "S-1-5-21-1-2-3-500";
        const string Anna = "S-1-12-1-1111-2222-3333-4444";

        static void Check(bool ok, string what)
        {
            T.Check(ok, "review: " + what);
        }

        static PolicySetting Find(Snapshot s, string layer, string area, string name)
        {
            foreach (PolicySetting p in s.Settings)
                if (p.Layer == layer && string.Equals(p.Area, area, StringComparison.OrdinalIgnoreCase) && p.Name == name) return p;
            return null;
        }

        static void Mdm(FakeRegistry r, string area, string name, string kind, string value)
        {
            r.Set(Pm + @"\current\device\" + area, name, kind, value);
            r.Set(Pm + @"\current\device\" + area, name + "_WinningProvider", "REG_SZ", Intune);
            r.Set(Pm + @"\providers\" + Intune + @"\default\Device\" + area, name, kind, value);
        }

        public static void Run()
        {
            FakeRegistry r = new FakeRegistry();
            string en = @"HKLM\SOFTWARE\Microsoft\Enrollments\" + Intune;
            r.Set(en, "ProviderID", "REG_SZ", "MS DM Server");
            r.Set(en, "UPN", "REG_SZ", "anna@contoso.com");

            // An ADMX-backed setting in a regular area, and one in an ADMX_ area whose file has another name.
            Mdm(r, "DeviceInstallation", "PreventInstallationOfMatchingDeviceIDs", "REG_SZ", "<enabled/><data id=\"DeviceInstall_IDs_Deny_List\" value=\"1&#xF000;USB\\VID_1234\"/>");
            Mdm(r, "ADMX_MicrosoftDefenderAntivirus", "DisableAntiSpywareDefender", "REG_SZ", "<disabled/>");
            Mdm(r, "WindowsLogon", "HideFastUserSwitching", "REG_DWORD", "1");
            r.Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "DenyDeviceIDs", "REG_DWORD", "1");
            r.Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs", "1", "REG_SZ", @"USB\VID_1234");
            r.Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "REG_DWORD", "0");
            r.Set(@"HKLM\SOFTWARE\Policies\Microsoft\Unknown", "Leftover", "REG_DWORD", "1");

            // CurrentVersion\Policies: a GPO value and a Windows default.
            string cv = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            r.Set(cv, "HideFastUserSwitching", "REG_DWORD", "0");
            r.Set(cv, "EnableLUA", "REG_DWORD", "1");

            // PolicyVice runs as an administrator account; Anna is signed in.
            r.Set(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI", "LastLoggedOnUserSID", "REG_SZ", Anna);
            r.Set(@"HKU\" + Anna + @"\SOFTWARE\Policies\Microsoft\Office\16.0\Common", "QMEnable", "REG_DWORD", "0");

            FakeRsop gp = new FakeRsop();
            gp.Add(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "HideFastUserSwitching", "0", "Workstations - Logon", 1);

            FakeEvents ev = new FakeEvents();
            for (int i = 0; i < 3; i++)
            {
                EventItem e = new EventItem();
                e.Time = new DateTime(2026, 11, 9, 6, i, 0);
                e.Id = 404;
                e.Level = "Error";
                e.Message = "MDM ConfigurationManager: Command failure status. Configuration Source ID: (" + Intune + "), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), Command Type: (CmdType_Add), CSP URI: (./Device/Vendor/MSFT/Policy/Config/Update/DeferQualityUpdatesPeriodInDays), Result: (The parameter is incorrect.).";
                ev.Items.Add(e);
            }

            AdmxCatalog admx = new AdmxCatalog();
            admx.Load("DeviceInstallation",
                "<policyDefinitions><policies><policy name=\"DeviceInstall_IDs_Deny\" class=\"Machine\" displayName=\"Prevent installation of devices that match any of these device IDs\" key=\"Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\" valueName=\"DenyDeviceIDs\"><elements><list id=\"DeviceInstall_IDs_Deny_List\" key=\"Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyDeviceIDs\" valuePrefix=\"\"/></elements></policy></policies></policyDefinitions>",
                null, false);
            admx.Load("WindowsDefender",
                "<policyDefinitions><policies><policy name=\"DisableAntiSpywareDefender\" class=\"Machine\" displayName=\"Turn off Microsoft Defender Antivirus\" key=\"Software\\Policies\\Microsoft\\Windows Defender\" valueName=\"DisableAntiSpyware\"/></policies></policyDefinitions>",
                null, false);

            CollectOptions o = new CollectOptions();
            o.CurrentUserSid = Admin;
            o.EventDays = 7;
            o.NowUtc = new DateTime(2026, 11, 9, 7, 0, 0, DateTimeKind.Utc);
            Snapshot s = Collector.Collect(r, gp, ev, admx, o);

            PolicySetting deny = Find(s, Layers.Registry, @"Microsoft\Windows\DeviceInstall\Restrictions", "DenyDeviceIDs");
            Check(deny != null && deny.Source == Sources.MdmAdmx && deny.SourceDetail == "DeviceInstallation/PreventInstallationOfMatchingDeviceIDs", "ADMX-backed setting in a regular area owns its value");
            Check(deny != null && !deny.Has(FindingKinds.Unmanaged), "no false Unmanaged");
            PolicySetting item = Find(s, Layers.Registry, @"Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs", "1");
            Check(item != null && item.Source == Sources.MdmAdmx, "values of an ADMX list belong to the policy");
            PolicySetting def = Find(s, Layers.Registry, @"Microsoft\Windows Defender", "DisableAntiSpyware");
            Check(def != null && def.Source == Sources.MdmAdmx, "ADMX_ area with another file name owns its value");
            PolicySetting left = Find(s, Layers.Registry, @"Microsoft\Unknown", "Leftover");
            Check(left != null && left.Has(FindingKinds.Unmanaged), "a real leftover is still Unmanaged");

            PolicySetting hide = Find(s, Layers.Registry, @"Microsoft\Windows\CurrentVersion\Policies\System", "HideFastUserSwitching");
            Check(hide != null && hide.Source == Sources.GroupPolicy && hide.SourceDetail == "Workstations - Logon", "CurrentVersion\\Policies value from a GPO");
            Check(hide != null && hide.PolicyKey == @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "policy key kept");
            PolicySetting mdmHide = Find(s, Layers.Mdm, "WindowsLogon", "HideFastUserSwitching");
            Check(hide != null && hide.Has(FindingKinds.Conflict) && mdmHide != null && mdmHide.Has(FindingKinds.Conflict), "HideFastUserSwitching conflict between Intune and a GPO");
            PolicySetting lua = Find(s, Layers.Registry, @"Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            Check(lua != null && lua.Source == Sources.Unknown && lua.Findings.Count == 0, "Windows defaults are not flagged");

            PolicySetting defer = Find(s, Layers.Mdm, "Update", "DeferQualityUpdatesPeriodInDays");
            Check(defer != null && defer.Has(FindingKinds.Error) && defer.Findings.Count == 1, "a failed setting that was never applied is shown once");
            Check(defer != null && defer.Findings[0].Message.StartsWith("Failed 3 times") && defer.Findings[0].Message.Contains("06:02:00"), "failure count and newest event");
            Check(s.Count(FindingKinds.Error) == 1, "error count");

            PolicySetting q = Find(s, Layers.Registry, @"Microsoft\Office\16.0\Common", "QMEnable");
            Check(q != null && q.Scope == "User" && q.UserSid == Anna, "the signed-in user's policy is read");
            bool noted = false;
            foreach (string n in s.Notes) if (n.Contains("not as the signed-in user")) noted = true;
            Check(noted, "running as another account is noted");

            List<Change> none = Differ.Compare(s, s);
            Check(none.Count == 0, "keys stay unique across both policy roots");
        }
    }
}
