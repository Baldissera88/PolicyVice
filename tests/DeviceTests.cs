namespace PolicyVice.Tests
{
    using System;

    public sealed class FakeJoin : IJoinSource
    {
        public JoinState State = new JoinState();
        public bool Throw;

        public JoinState Read()
        {
            if (Throw) throw new DllNotFoundException("netapi32.dll");
            return State;
        }
    }

    public static class DeviceTests
    {
        const string Tenant = "8a1b3c2d-0000-4000-8000-00000000c0de";
        const string IntuneId = "3A1B2C3D-0000-4000-8000-000000000001";
        const string Thumb = "0855B7D71E09C7D8E5484F8A00260D795BE28E33";

        static void Check(bool ok, string what)
        {
            T.Check(ok, "device: " + what);
        }

        static FakeRegistry Registry()
        {
            FakeRegistry r = new FakeRegistry();
            string cv = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            r.Set(cv, "ProductName", "REG_SZ", "Windows 10 Enterprise");
            r.Set(cv, "EditionID", "REG_SZ", "Enterprise");
            r.Set(cv, "DisplayVersion", "REG_SZ", "25H2");
            r.Set(cv, "CurrentBuild", "REG_SZ", "26200");
            r.Set(cv, "UBR", "REG_DWORD", "7171");
            string join = @"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\" + Thumb;
            r.Set(join, "TenantId", "REG_SZ", Tenant);
            r.Set(join, "UserEmail", "REG_SZ", "anna@contoso.com");
            r.Set(join, "IdpDomain", "REG_SZ", "login.windows.net");
            string ti = @"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\" + Tenant;
            r.Set(ti, "MdmEnrollmentUrl", "REG_SZ", "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc");
            r.Set(ti, "MdmComplianceUrl", "REG_SZ", "https://portal.manage.microsoft.com/?portalAction=Compliance");
            string e = @"HKLM\SOFTWARE\Microsoft\Enrollments\";
            r.Set(e + "Context", "x", "REG_SZ", "y");
            r.Set(e + "11111111-0000-4000-8000-000000000009", "ProviderID", "REG_SZ", "MicrosoftManagementPlatformCloud");
            r.Set(e + IntuneId, "ProviderID", "REG_SZ", "MS DM Server");
            r.Set(e + IntuneId, "UPN", "REG_SZ", "anna@contoso.com");
            r.Set(e + IntuneId + @"\DMClient\MS DM Server", "EntDMID", "REG_SZ", "b2f1c0de-1111-2222-3333-444455556666");
            string conn = @"HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\" + IntuneId + @"\Protected\ConnInfo";
            r.Set(conn, "ServerLastSuccessTime", "REG_SZ", "20261108T072908Z");
            r.Set(conn, "ServerLastAccessTime", "REG_SZ", "20261108T082908Z");
            r.Set(@"HKLM\SOFTWARE\Microsoft\SMS\Mobile Client", "ProductVersion", "REG_SZ", "5.00.9135.1000");
            r.Set(@"HKLM\SOFTWARE\Microsoft\SMS\Mobile Client", "AssignedSiteCode", "REG_SZ", "P01");
            r.Set(@"HKLM\SOFTWARE\Microsoft\CCM", "CoManagementFlags", "REG_DWORD", "8193");
            return r;
        }

        static FakeJoin Join(int aad, int net, string name)
        {
            FakeJoin j = new FakeJoin();
            j.State.AadJoinType = aad;
            j.State.NetJoinStatus = net;
            j.State.NetJoinName = name;
            if (aad == 1)
            {
                j.State.TenantId = Tenant;
                j.State.TenantName = "Contoso";
                j.State.DeviceId = "d0d0d0d0-1111-2222-3333-444444444444";
                j.State.IdpDomain = "login.windows.net";
                j.State.JoinUserEmail = "anna@contoso.com";
                j.State.MdmEnrollmentUrl = "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc";
                j.State.MdmComplianceUrl = "https://portal.manage.microsoft.com/?portalAction=Compliance";
            }
            return j;
        }

        static string Type(DeviceInfo d)
        {
            return d.Get("Join type");
        }

        public static void Run()
        {
            FakeRegistry r = Registry();

            DeviceInfo d = DeviceCollector.Collect(r, Join(1, 2, "WORKGROUP"));
            Check(Type(d) == "Microsoft Entra joined", "Entra joined");
            Check(d.Get("Tenant ID") == Tenant && d.Get("Tenant name") == "Contoso" && d.Get("Device ID") == "d0d0d0d0-1111-2222-3333-444444444444", "tenant and device ID from the API");
            Check(d.Get("Windows") == "Windows 11 Enterprise" && d.Get("Edition") == "Enterprise" && d.Get("Version") == "25H2" && d.Get("Build") == "26200.7171", "Windows version");
            Check(d.Get("Intune enrollment") == IntuneId && d.Get("Enrolled user") == "anna@contoso.com", "Intune enrollment, not MMP-C");
            Check(d.Get("Intune device ID") == "b2f1c0de-1111-2222-3333-444455556666", "Intune device ID");
            Check(d.Get("Last successful sync") == "2026-11-08 07:29:08 UTC" && d.Get("Last sync attempt") == "2026-11-08 08:29:08 UTC", "last sync");
            Check(d.Get("MDM compliance URL").Contains("portalAction=Compliance"), "compliance URL");
            Check(d.Get("Client") == "Installed" && d.Get("Client version") == "5.00.9135.1000" && d.Get("Site code") == "P01" && d.Get("Co-management") == "Configured (flags 8193)", "Configuration Manager client");
            Check(d.Items.Exists(delegate (InfoItem i) { return i.Group == DeviceCollector.GEntra; }) && d.Items.Exists(delegate (InfoItem i) { return i.Group == DeviceCollector.GConfigMgr; }), "groups");

            DeviceInfo h = DeviceCollector.Collect(r, Join(1, 3, "CONTOSO"));
            Check(Type(h) == "Microsoft Entra hybrid joined" && h.Get("Domain") == "CONTOSO", "hybrid joined");
            Check(Type(DeviceCollector.Collect(r, Join(0, 3, "CONTOSO"))) == "Domain joined", "domain joined");
            Check(Type(DeviceCollector.Collect(r, Join(2, 3, "CONTOSO"))) == "Domain joined, Microsoft Entra registered", "domain joined and registered");
            Check(Type(DeviceCollector.Collect(r, Join(2, 2, "WORKGROUP"))) == "Microsoft Entra registered", "Entra registered");
            DeviceInfo w = DeviceCollector.Collect(r, Join(0, 2, "WORKGROUP"));
            Check(Type(w) == "Workgroup" && w.Get("Workgroup") == "WORKGROUP", "workgroup");

            // No API: only what the registry proves.
            DeviceInfo nr = DeviceCollector.Collect(r, null);
            Check(Type(nr) == "Microsoft Entra joined (domain join not read)" && nr.Get("Tenant ID") == Tenant && nr.Get("Device ID") == null, "registry only join");
            Check(nr.Get("MDM enrollment URL").StartsWith("https://enrollment.manage.microsoft.com") && nr.Get("Join user") == "anna@contoso.com", "registry tenant info");
            FakeJoin broken = new FakeJoin();
            broken.Throw = true;
            Check(Type(DeviceCollector.Collect(r, broken)) == "Microsoft Entra joined (domain join not read)", "join API failure falls back to registry");
            Check(Type(DeviceCollector.Collect(new FakeRegistry(), null)) == "Unknown", "nothing known");

            FakeRegistry empty = new FakeRegistry();
            DeviceInfo e = DeviceCollector.Collect(empty, Join(0, 2, "WORKGROUP"));
            Check(e.Get("Client") == "Not found" && e.Get("Co-management") == null && e.Get("Intune enrollment") == "Not found" && e.Get("Windows") == null, "no client and no enrollment");

            // Denied keys do not break the collection.
            FakeRegistry den = Registry();
            den.Block(@"HKLM\SOFTWARE\Microsoft\Enrollments");
            DeviceInfo dd = DeviceCollector.Collect(den, null);
            Check(dd.Get("Intune enrollment") == "Not found" && dd.Get("Windows") == "Windows 11 Enterprise" && den.Denied.Count == 1, "denied enrollments key");

            Check(DeviceCollector.SyncTime(new RegValue("REG_BINARY", "00 80 3E D5 DE B1 9D 01")) == "1970-01-01 00:00:00 UTC", "FILETIME sync time");
            Check(DeviceCollector.SyncTime(new RegValue("REG_SZ", "not a time")) == "not a time" && DeviceCollector.SyncTime(null) == null, "unknown sync time format kept");

            // The live join API must not throw where netapi32.dll is missing.
            bool threw = false;
            try { new LiveJoin().Read(); } catch (Exception) { threw = true; }
            Check(!threw, "live join API is safe");

            // The collector fills device information without calling the API for a fake registry.
            CollectOptions o = new CollectOptions();
            Snapshot s = Collector.Collect(r, null, null, null, o);
            Check(s.Device.Get("Join type") == "Microsoft Entra joined (domain join not read)" && s.Device.Get("Intune device ID") != null, "device information in the snapshot");
        }
    }
}
