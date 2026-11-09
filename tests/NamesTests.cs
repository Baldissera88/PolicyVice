namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    public static class NamesTests
    {
        static void Check(bool ok, string what)
        {
            T.Check(ok, "names: " + what);
        }

        public static void Run()
        {
            // The Entra object ID maps to the S-1-12-1 SID Windows uses for that user.
            string sid = Names.SidFromObjectId("9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9");
            Check(sid == "S-1-12-1-2585472061-1618038367-3047461762-4192786374", "object ID to SID: " + sid);
            Check(Names.SidFromObjectId("System") == null, "not a GUID");

            FakeRegistry r = new FakeRegistry();
            r.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\E1", "SID", "REG_SZ", "S-1-12-1-1-2-3-4");
            r.Set(@"HKLM\SOFTWARE\Microsoft\Enrollments\E1", "UPN", "REG_SZ", "anna@contoso.com");
            r.Set(@"HKLM\SOFTWARE\Microsoft\IdentityStore\Cache\" + sid + @"\IdentityCache\" + sid, "UserName", "REG_SZ", "bo@contoso.com");
            r.Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-9-9-9-1001", "ProfileImagePath", "REG_EXPAND_SZ", @"C:\Users\carl");
            Names.Users u = new Names.Users(r, new Snapshot());
            Check(u.Name("S-1-12-1-1-2-3-4") == "anna@contoso.com", "user from enrollment");
            Check(u.NameForObjectId("9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9") == "bo@contoso.com", "user from sign-in cache");
            Check(u.Name("S-1-5-21-9-9-9-1001") == "carl", "user from profile");
            Check(u.Name("S-1-5-21-0-0-0-1") == null, "unknown user");

            Check(Names.Area("ADMX_TerminalServer") == "Terminal Server (ADMX)", "ADMX area: " + Names.Area("ADMX_TerminalServer"));
            Check(Names.Area("OneDriveNGSCv2~Policy~OneDriveNGSC") == "OneDrive: One Drive NGSC", "ingested area: " + Names.Area("OneDriveNGSCv2~Policy~OneDriveNGSC"));
            Check(Names.Area("office16v2~Policy~L_MicrosoftOfficeSystem~L_SecuritySettings") == "Office 16: Microsoft Office System > Security Settings", "Office area");
            Check(Names.Area("LocalPoliciesSecurityOptions") == "Local Policies Security Options", "CSP area");
            Check(Names.AdmxValue("<enabled/><data id=\"KFMSilentOptInBox\" value=\"tenant-id\"/>") == "Enabled, KFM Silent Opt In Box: tenant-id", "ADMX value: " + Names.AdmxValue("<enabled/><data id=\"KFMSilentOptInBox\" value=\"tenant-id\"/>"));
            Check(Names.AdmxValue("<disabled/>") == "Disabled", "disabled");
            Check(Names.AdmxValue("<enabled/><data id=\"List\" value=\"a&#xF000;b\"/>") == "Enabled, List: a, b", "list value");
            Check(Names.AdmxValue("1") == null, "plain value");

            PolicySetting p = new PolicySetting();
            p.Value = "<enabled/>";
            p.ValueMeaning = "Enabled";
            Check(p.DisplayValue == "Enabled", "ADMX display value in words");
            p.Value = "1";
            p.ValueMeaning = "Allowed";
            Check(p.DisplayValue == "1 (Allowed)", "number with meaning");

            string dir = Path.Combine(Path.GetTempPath(), "policyvice-names");
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, "names.tsv");
            Dictionary<string, string> names = new Dictionary<string, string>();
            names["11111111-2222-3333-4444-555555555555"] = "7-Zip 24.08";
            names["aaaaaaaa-2222-3333-4444-555555555555"] = "Remediation\twith tab";
            NameCache.SaveFile(file, names);
            Dictionary<string, string> back = NameCache.LoadFile(file);
            Check(back.Count == 2 && back["11111111-2222-3333-4444-555555555555"] == "7-Zip 24.08", "cache round trip");
            Check(back["AAAAAAAA-2222-3333-4444-555555555555"] == "Remediation with tab", "cache ignores case and tabs");
            Check(NameCache.LoadFile(Path.Combine(dir, "missing.tsv")).Count == 0, "missing cache");

            List<ImeItem> items = new List<ImeItem>();
            ImeItem a = new ImeItem();
            a.Id = "11111111-2222-3333-4444-555555555555";
            a.Name = "old name from the log";
            ImeItem b = new ImeItem();
            b.Id = "aaaaaaaa-2222-3333-4444-555555555555_2";
            ImeItem c = new ImeItem();
            c.Id = "bbbbbbbb-2222-3333-4444-555555555555";
            items.Add(a);
            items.Add(b);
            items.Add(c);
            Check(NameCache.Apply(items, back) == 2, "names applied");
            Check(a.Name == "7-Zip 24.08" && b.Name == "Remediation with tab" && c.Name == null, "Graph names win, revision ignored");
        }
    }
}
