namespace PolicyVice.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Text;

    public static class CatalogTests
    {
        public static void Run()
        {
            Embedded();
            SpotChecks();
            Registry();
            Loading();
            Describe();
        }

        static CspEntry Get(CspCatalog c, string area, string name)
        {
            CspEntry e = c.Find(area, name);
            T.Check(e != null, "catalog has " + area + "/" + name);
            return e ?? new CspEntry();
        }

        static bool Same(string a, string b)
        {
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        static bool Has(List<CspEntry> l, string area, string name)
        {
            foreach (CspEntry e in l) if (Same(e.Area, area) && Same(e.Name, name)) return true;
            return false;
        }

        static void Embedded()
        {
            CspCatalog c = CspCatalog.Embedded();
            T.Check(c.Count > 2500 && c.Count < 20000, "embedded catalog has a realistic count (" + c.Count + ")");
            T.Check(object.ReferenceEquals(c, CspCatalog.Embedded()), "embedded catalog is loaded once");
            T.Check(c.Entries.Count == c.Count, "entries match the count");
            T.Check(!string.IsNullOrEmpty(c.Commit) && c.Commit.Length == 40, "catalog records the docs commit");
            T.Check(c.Source.IndexOf(c.Commit.Substring(0, 12), StringComparison.Ordinal) >= 0 && c.Source.IndexOf("CC BY 4.0", StringComparison.Ordinal) >= 0, "source names the commit and license: " + c.Source);
            T.Check(c.Meta("entries") == c.Count.ToString(), "header entry count matches the rows");
            int admx = 0, user = 0, both = 0, mapped = 0;
            foreach (CspEntry e in c.Entries)
            {
                if (e.Area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase)) admx++;
                if (e.Scope == "User") user++;
                if (e.Scope == "Both") both++;
                if (!string.IsNullOrEmpty(e.GpKey)) mapped++;
            }
            T.Check(admx > 1500 && user > 300 && both > 300 && mapped > 2000, "catalog covers ADMX_ areas, user and both scopes, and registry keys");
        }

        static void SpotChecks()
        {
            CspCatalog c = CspCatalog.Embedded();

            CspEntry u = Get(c, "Update", "AllowAutoUpdate");
            T.Check(object.ReferenceEquals(u, c.Find("update", "ALLOWAUTOUPDATE")), "Find ignores case");
            T.Check(c.Find("Update", "NoSuchPolicy") == null && c.Find(null, "AllowAutoUpdate") == null, "Find returns null for unknown settings");
            T.Check(u.FriendlyName == "Configure Automatic Updates", "AllowAutoUpdate friendly name: " + u.FriendlyName);
            T.Check(u.Scope == "Device" && u.Format == "int" && u.Default == "2", "AllowAutoUpdate scope, format and default");
            T.Check(u.ValueOrder.Count == 6 && u.ValueOrder[0] == "0" && u.ValueOrder[5] == "5", "AllowAutoUpdate has values 0 to 5 in order");
            T.Check(u.Values.ContainsKey("0") && u.Values["0"].StartsWith("Notify the user before downloading", StringComparison.Ordinal), "AllowAutoUpdate value 0 meaning");
            T.Check(u.Values.ContainsKey("2") && u.Values["2"].StartsWith("Auto install and restart", StringComparison.Ordinal), "AllowAutoUpdate value 2 meaning");
            T.Check(u.Values.ContainsKey("5") && u.Values["5"] == "Turn off automatic updates.", "AllowAutoUpdate value 5 meaning");
            T.Check(u.AdmxFile == "WindowsUpdate.admx" && u.AdmxPolicy == "AutoUpdateCfg" && !u.AdmxBacked, "AllowAutoUpdate ADMX mapping");
            T.Check(Same(u.GpKey, @"Software\Policies\Microsoft\Windows\WindowsUpdate\AU"), "AllowAutoUpdate registry key: " + u.GpKey);
            T.Check(u.GpPath == "Windows Components > Windows Update > Manage end user experience" && u.GpLocation == "Computer Configuration", "AllowAutoUpdate Group Policy path");
            T.Check(u.Description != null && u.Description.StartsWith("Enables the IT admin to manage automatic update behavior", StringComparison.Ordinal), "AllowAutoUpdate description");
            T.Check(u.Uri == "Policy/Config/Update/AllowAutoUpdate", "entry URI");

            CspEntry d = Get(c, "Defender", "AllowRealtimeMonitoring");
            T.Check(d.FriendlyName == "Turn off real-time protection" && d.Scope == "Device", "AllowRealtimeMonitoring name and scope");
            T.Check(d.Values.Count == 2 && d.Values["0"].StartsWith("Not allowed", StringComparison.Ordinal) && d.Values["1"].StartsWith("Allowed", StringComparison.Ordinal), "AllowRealtimeMonitoring values");
            T.Check(Same(d.GpKey, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection") && d.GpValueName == "DisableRealtimeMonitoring" && d.AdmxFile == "WindowsDefender.admx", "AllowRealtimeMonitoring Group Policy mapping");

            CspEntry x = Get(c, "Experience", "AllowCortana");
            T.Check(x.FriendlyName == "Allow Cortana" && x.Default == "1", "AllowCortana name and default");
            T.Check(Same(x.GpKey, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search") && x.GpValueName == "AllowCortana" && x.AdmxFile == "Search.admx", "AllowCortana Group Policy mapping");

            CspEntry o = Get(c, "DeliveryOptimization", "DODownloadMode");
            T.Check(o.FriendlyName == "Download Mode" && o.Default == "0" && o.AdmxPolicy == "DownloadMode", "DODownloadMode name, default and ADMX policy");
            T.Check(o.Values.ContainsKey("1") && o.Values["1"] == "HTTP blended with peering behind the same NAT." && o.Values.ContainsKey("99") && o.Values.ContainsKey("100"), "DODownloadMode values");
            T.Check(Same(o.GpKey, @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization") && o.GpElement == "Download Mode.", "DODownloadMode registry key and element");

            CspEntry b = Get(c, "ADMX_Bits", "BITS_DisableBranchCache");
            T.Check(b.AdmxBacked && b.AdmxFile == "Bits.admx" && b.AdmxPolicy == "BITS_DisableBranchCache", "ADMX_Bits entry is ADMX-backed");
            T.Check(b.FriendlyName == "Do not allow the BITS client to use Windows Branch Cache" && b.Scope == "Device", "ADMX_Bits friendly name and scope");
            T.Check(Same(b.GpKey, @"Software\Policies\Microsoft\Windows\BITS") && b.GpValueName == "DisableBranchCache", "ADMX_Bits registry mapping");

            CspEntry s = Get(c, "Experience", "AllowWindowsSpotlight");
            T.Check(s.Scope == "User" && s.AppliesTo("User") && !s.AppliesTo("Device"), "AllowWindowsSpotlight is user scope");
            T.Check(s.GpLocation == "User Configuration" && s.GpValueName == "DisableWindowsSpotlightFeatures", "AllowWindowsSpotlight Group Policy mapping");

            CspEntry ie = Get(c, "InternetExplorer", "AllowActiveXFiltering");
            T.Check(ie.Scope == "Both" && ie.AppliesTo("Device") && ie.AppliesTo("User"), "InternetExplorer/AllowActiveXFiltering is device and user scope");

            CspEntry f = Get(c, "Feeds", "FeedsEnabled");
            T.Check(f.FriendlyName == "Enable news and interests on the taskbar" && f.AdmxFile == "Feeds.admx", "legacy-format Feeds page is parsed");

            CspEntry n = Get(c, "LocalPoliciesSecurityOptions", "Accounts_BlockMicrosoftAccounts");
            T.Check(n.FriendlyName == "Accounts: Block Microsoft accounts" && n.AdmxPolicy == null && n.GpKey == null, "security option keeps its Group Policy name without a registry mapping");

            int markup = 0;
            foreach (CspEntry e in c.Entries)
            {
                string t = (e.Description ?? "") + (e.FriendlyName ?? "");
                if (t.IndexOf("**", StringComparison.Ordinal) >= 0 || t.IndexOf("](", StringComparison.Ordinal) >= 0 || t.IndexOf("<!--", StringComparison.Ordinal) >= 0 || t.IndexOf("[!", StringComparison.Ordinal) >= 0) markup++;
            }
            T.Check(markup == 0, "descriptions are plain text (" + markup + " with markup)");
        }

        static void Registry()
        {
            CspCatalog c = CspCatalog.Embedded();
            T.Check(Has(c.FindByRegistry(@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"), "Defender", "AllowRealtimeMonitoring"), "FindByRegistry with HKLM prefix");
            T.Check(Has(c.FindByRegistry(@"HKEY_LOCAL_MACHINE\Software\policies\microsoft\windows defender\real-time protection\", "disablerealtimemonitoring"), "Defender", "AllowRealtimeMonitoring"), "FindByRegistry with long hive and other casing");
            T.Check(Has(c.FindByRegistry(@"software\policies\microsoft\windows\windows search", "AllowCortana"), "Experience", "AllowCortana"), "FindByRegistry without hive");
            T.Check(Has(c.FindByRegistry(@"HKU\S-1-5-21-1-2-3-1001\Software\Policies\Microsoft\Windows\CloudContent", "DisableWindowsSpotlightFeatures"), "Experience", "AllowWindowsSpotlight"), "FindByRegistry with HKU and SID");
            T.Check(Has(c.FindByRegistry(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", null), "Update", "AllowAutoUpdate"), "FindByRegistry with a null value name returns every setting under the key");
            T.Check(c.FindByRegistry(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoSuchValue").Count == 0, "FindByRegistry does not match other value names");
            T.Check(c.FindByRegistry(@"HKLM\SOFTWARE\Policies\Nobody", "X").Count == 0 && c.FindByRegistry(null, "X").Count == 0, "FindByRegistry returns an empty list when nothing matches");
            T.Check(Has(c.FindByAdmx("WindowsUpdate", "AutoUpdateCfg"), "Update", "AllowAutoUpdate") && Has(c.FindByAdmx("windowsupdate.admx", "AutoUpdateCfg"), "Update", "AllowAutoUpdate"), "FindByAdmx with and without .admx");
            T.Check(CspCatalog.NormKey(@"HKEY_CURRENT_USER\SOFTWARE\Policies\A\\B\") == @"software\policies\a\b", "NormKey strips the hive and doubled separators");
        }

        static Stream Gzip(string text)
        {
            MemoryStream m = new MemoryStream();
            using (GZipStream gz = new GZipStream(m, CompressionMode.Compress, true))
            {
                byte[] b = new UTF8Encoding(false).GetBytes(text);
                gz.Write(b, 0, b.Length);
            }
            m.Position = 0;
            return m;
        }

        static void Loading()
        {
            string tsv = "#commit\tabc123\n#date\t2025-07-09\n#source\thttps://example.invalid/docs\n"
                + "Name\tArea\tScope\tFriendlyName\tDescription\tValues\tGpKey\tGpValueName\tAdmxBacked\tExtra\n"
                + "Thing\tTest\tDevice\tTab\\there\tLine\\none \\\\ back\t0\\tOff.\\n1\\tOn. Really on.\tSOFTWARE\\\\Policies\\\\Test\tThingValue\t1\tz\n"
                + "Other\ttest\tUser\t\t\t\t\t\t\t\n"
                + "Thing\tTest\tUser\tDuplicate\t\t\t\t\t\t\n";
            CspCatalog c = CspCatalog.Load(Gzip(tsv));
            T.Check(c.Count == 2, "Load reads rows by column name and skips duplicates (" + c.Count + ")");
            CspEntry e = c.Find("TEST", "thing");
            T.Check(e != null && e.FriendlyName == "Tab\there" && e.Description == "Line\none \\ back", "Load unescapes tabs, newlines and backslashes");
            T.Check(e != null && e.AdmxBacked && e.GpKey == @"SOFTWARE\Policies\Test" && e.Values.Count == 2 && e.Values["1"] == "On. Really on.", "Load reads values and mapping");
            T.Check(e != null && e.Format == null && e.Range == null, "missing columns are null");
            T.Check(c.Commit == "abc123" && c.Date == "2025-07-09" && c.Source.IndexOf("example.invalid/docs commit abc123 (2025-07-09)", StringComparison.Ordinal) >= 0, "Load reads the header: " + c.Source);
            T.Check(c.FindByRegistry(@"HKLM\Software\Policies\Test", "thingvalue").Count == 1, "Load indexes registry keys");
            T.Check(CspCatalog.Load(null).Count == 0, "Load(null) gives an empty catalog");
            T.Check(CspCatalog.Load(new MemoryStream(Encoding.ASCII.GetBytes("not gzip at all"))).Count == 0, "Load of a bad stream gives an empty catalog");
            T.Check(new CspCatalog().Source == "No Policy CSP catalog", "empty catalog source");
        }

        static void Describe()
        {
            CspCatalog c = CspCatalog.Embedded();
            CspEntry u = c.Find("Update", "AllowAutoUpdate");
            T.Check(CspCatalog.Describe(u, "5") == "5 (Turn off automatic updates)", "Describe gives the value with its meaning: " + CspCatalog.Describe(u, "5"));
            T.Check(CspCatalog.Describe(c.Find("Experience", "AllowCortana"), "0") == "0 (Not allowed)", "Describe drops the final full stop");
            T.Check(CspCatalog.Describe(c.Find("Defender", "AllowRealtimeMonitoring"), "1") == "1 (Allowed. Turns on and runs the real-time monitoring service.)", "Describe keeps longer meanings whole");
            T.Check(CspCatalog.Describe(u, "0x5") == "0x5 (Turn off automatic updates)" && CspCatalog.Describe(u, " 05") == " 05 (Turn off automatic updates)", "Describe matches hex and padded numbers");
            T.Check(CspCatalog.Describe(u, "7") == "7" && CspCatalog.Describe(null, "1") == "1" && CspCatalog.Describe(u, null) == null, "Describe returns unknown values as is");
            T.Check(CspCatalog.Meaning(c.Find("DeliveryOptimization", "DODownloadMode"), "99") == "HTTP only, no peering, no use of DO cloud service", "Meaning without the value");
        }
    }
}
