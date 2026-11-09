namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Runtime.InteropServices;
    using System.Runtime.Serialization;

    // One line of device information, shown grouped on the Device tab.
    [DataContract]
    public sealed class InfoItem
    {
        [DataMember] public string Group;
        [DataMember] public string Label;
        [DataMember] public string Value;

        public InfoItem() { }

        public InfoItem(string group, string label, string value)
        {
            Group = group;
            Label = label;
            Value = value;
        }
    }

    [DataContract]
    public sealed class DeviceInfo
    {
        [DataMember] public List<InfoItem> Items = new List<InfoItem>();

        public void Add(string group, string label, string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            Items.Add(new InfoItem(group, label, value));
        }

        public string Get(string label)
        {
            foreach (InfoItem i in Items) if (i.Label == label) return i.Value;
            return null;
        }
    }

    // Join state from the Windows APIs NetGetJoinInformation and NetGetAadJoinInformation. -1 means not read.
    public sealed class JoinState
    {
        public int NetJoinStatus = -1;      // NETSETUP_JOIN_STATUS: 0 unknown, 1 unjoined, 2 workgroup, 3 domain
        public string NetJoinName;
        public int AadJoinType = -1;        // DSREG_JOIN_TYPE: 0 none or unknown, 1 Entra joined, 2 Entra registered
        public string DeviceId;
        public string TenantId;
        public string TenantName;
        public string IdpDomain;
        public string JoinUserEmail;
        public string MdmEnrollmentUrl;
        public string MdmComplianceUrl;
        public string MdmTermsOfUseUrl;
    }

    public interface IJoinSource
    {
        JoinState Read();
    }

    // Calls netapi32.dll. Every failure leaves the fields at -1 or null, so the registry is used instead.
    public sealed class LiveJoin : IJoinSource
    {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetGetJoinInformation(string server, out IntPtr name, out int status);

        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetGetAadJoinInformation(string tenantId, out IntPtr info);

        [DllImport("netapi32.dll")]
        static extern void NetFreeAadJoinInformation(IntPtr info);

#pragma warning disable 0649
        [StructLayout(LayoutKind.Sequential)]
        struct DsregJoinInfo
        {
            public int joinType;
            public IntPtr pJoinCertificate;
            public IntPtr pszDeviceId;
            public IntPtr pszIdpDomain;
            public IntPtr pszTenantId;
            public IntPtr pszJoinUserEmail;
            public IntPtr pszTenantDisplayName;
            public IntPtr pszMdmEnrollmentUrl;
            public IntPtr pszMdmTermsOfUseUrl;
            public IntPtr pszMdmComplianceUrl;
            public IntPtr pszUserSettingSyncUrl;
            public IntPtr pUserInfo;
        }
#pragma warning restore 0649

        public JoinState Read()
        {
            JoinState j = new JoinState();
            try
            {
                IntPtr name;
                int status;
                if (NetGetJoinInformation(null, out name, out status) == 0)
                {
                    j.NetJoinStatus = status;
                    if (name != IntPtr.Zero)
                    {
                        j.NetJoinName = Marshal.PtrToStringUni(name);
                        NetApiBufferFree(name);
                    }
                }
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            catch (Exception) { }
            try
            {
                IntPtr p;
                if (NetGetAadJoinInformation(null, out p) == 0)
                {
                    if (p == IntPtr.Zero) j.AadJoinType = 0;
                    else
                    {
                        try
                        {
                            DsregJoinInfo i = (DsregJoinInfo)Marshal.PtrToStructure(p, typeof(DsregJoinInfo));
                            j.AadJoinType = i.joinType;
                            j.DeviceId = Marshal.PtrToStringUni(i.pszDeviceId);
                            j.IdpDomain = Marshal.PtrToStringUni(i.pszIdpDomain);
                            j.TenantId = Marshal.PtrToStringUni(i.pszTenantId);
                            j.JoinUserEmail = Marshal.PtrToStringUni(i.pszJoinUserEmail);
                            j.TenantName = Marshal.PtrToStringUni(i.pszTenantDisplayName);
                            j.MdmEnrollmentUrl = Marshal.PtrToStringUni(i.pszMdmEnrollmentUrl);
                            j.MdmTermsOfUseUrl = Marshal.PtrToStringUni(i.pszMdmTermsOfUseUrl);
                            j.MdmComplianceUrl = Marshal.PtrToStringUni(i.pszMdmComplianceUrl);
                        }
                        finally { NetFreeAadJoinInformation(p); }
                    }
                }
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            catch (Exception) { }
            return j;
        }
    }

    // Reads join state, tenant, MDM and Configuration Manager details. Read-only. See docs/research/sources.md.
    public static class DeviceCollector
    {
        public const string GDevice = "Device";
        public const string GEntra = "Microsoft Entra ID";
        public const string GMdm = "MDM";
        public const string GConfigMgr = "Configuration Manager";

        const string CurrentVersion = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        const string JoinInfo = @"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo";
        const string TenantInfo = @"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo";
        const string OmaDm = @"HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts";
        const string SmsClient = @"HKLM\SOFTWARE\Microsoft\SMS\Mobile Client";
        const string Ccm = @"HKLM\SOFTWARE\Microsoft\CCM";

        // The join APIs are only called for the live registry, so tests and the demo never read the real device.
        public static DeviceInfo Collect(IRegSource reg)
        {
            return Collect(reg, reg is LiveRegistry ? new LiveJoin() : null);
        }

        public static DeviceInfo Collect(IRegSource reg, IJoinSource join)
        {
            DeviceInfo d = new DeviceInfo();
            JoinState j = null;
            if (join != null)
            {
                try { j = join.Read(); } catch (Exception) { j = null; }
            }
            Try(delegate { Windows(reg, d); });
            Try(delegate { Join(reg, d, j); });
            Try(delegate { Mdm(reg, d, j); });
            Try(delegate { ConfigMgr(reg, d); });
            return d;
        }

        delegate void Work();

        static void Try(Work w)
        {
            try { w(); } catch (Exception) { }
        }

        static void Windows(IRegSource reg, DeviceInfo d)
        {
            string product = Str(reg.Get(CurrentVersion, "ProductName"));
            string build = Str(reg.Get(CurrentVersion, "CurrentBuild"));
            string ubr = Str(reg.Get(CurrentVersion, "UBR"));
            int b;
            // ProductName still says Windows 10 on Windows 11. Windows 11 starts at build 22000.
            if (product != null && int.TryParse(build, NumberStyles.Integer, CultureInfo.InvariantCulture, out b) && b >= 22000)
                product = product.Replace("Windows 10", "Windows 11");
            d.Add(GDevice, "Windows", product);
            d.Add(GDevice, "Edition", Str(reg.Get(CurrentVersion, "EditionID")));
            d.Add(GDevice, "Version", Str(reg.Get(CurrentVersion, "DisplayVersion")));
            d.Add(GDevice, "Build", string.IsNullOrEmpty(build) ? null : build + (string.IsNullOrEmpty(ubr) ? "" : "." + ubr));
        }

        // JoinInfo\<certificate thumbprint> holds TenantId and UserEmail for an Entra join.
        static string JoinKey(IRegSource reg)
        {
            foreach (string k in reg.SubKeys(JoinInfo))
                if (!string.IsNullOrEmpty(Str(reg.Get(JoinInfo + "\\" + k, "TenantId")))) return JoinInfo + "\\" + k;
            return null;
        }

        static void Join(IRegSource reg, DeviceInfo d, JoinState j)
        {
            string joinKey = JoinKey(reg);
            bool apiAad = j != null && j.AadJoinType >= 0;
            bool apiNet = j != null && j.NetJoinStatus > 0;
            int entra = apiAad ? (j.AadJoinType == 1 ? 1 : 0) : (joinKey != null ? 1 : -1);
            int domain = apiNet ? (j.NetJoinStatus == 3 ? 1 : 0) : -1;
            bool registered = apiAad && j.AadJoinType == 2;

            string type;
            if (entra == 1 && domain == 1) type = "Microsoft Entra hybrid joined";
            else if (entra == 1 && domain == 0) type = "Microsoft Entra joined";
            else if (entra == 1) type = "Microsoft Entra joined (domain join not read)";
            else if (domain == 1) type = registered ? "Domain joined, Microsoft Entra registered" : "Domain joined";
            else if (domain == 0 && registered) type = "Microsoft Entra registered";
            else if (domain == 0) type = j.NetJoinStatus == 2 ? "Workgroup" : "Not joined";
            else type = "Unknown";
            d.Add(GDevice, "Join type", type);
            if (apiNet && j.NetJoinStatus == 3) d.Add(GDevice, "Domain", j.NetJoinName);
            if (apiNet && j.NetJoinStatus == 2) d.Add(GDevice, "Workgroup", j.NetJoinName);

            string tenant = j != null && !string.IsNullOrEmpty(j.TenantId) ? j.TenantId : joinKey != null ? Str(reg.Get(joinKey, "TenantId")) : null;
            d.Add(GEntra, "Tenant ID", tenant);
            if (j != null) d.Add(GEntra, "Tenant name", j.TenantName);
            if (j != null) d.Add(GEntra, "Device ID", j.DeviceId);
            string user = j != null && !string.IsNullOrEmpty(j.JoinUserEmail) ? j.JoinUserEmail : joinKey != null ? Str(reg.Get(joinKey, "UserEmail")) : null;
            d.Add(GEntra, "Join user", user);
            if (j != null) d.Add(GEntra, "Identity provider", j.IdpDomain);
        }

        static void Mdm(IRegSource reg, DeviceInfo d, JoinState j)
        {
            string tenant = j != null && !string.IsNullOrEmpty(j.TenantId) ? j.TenantId : null;
            if (tenant == null)
            {
                string joinKey = JoinKey(reg);
                if (joinKey != null) tenant = Str(reg.Get(joinKey, "TenantId"));
            }
            string ti = string.IsNullOrEmpty(tenant) ? null : TenantInfo + "\\" + tenant;
            // These URLs come from the tenant's MDM settings. They do not prove that the device is enrolled.
            d.Add(GMdm, "MDM enrollment URL", j != null && !string.IsNullOrEmpty(j.MdmEnrollmentUrl) ? j.MdmEnrollmentUrl : ti != null ? Str(reg.Get(ti, "MdmEnrollmentUrl")) : null);
            d.Add(GMdm, "MDM compliance URL", j != null && !string.IsNullOrEmpty(j.MdmComplianceUrl) ? j.MdmComplianceUrl : ti != null ? Str(reg.Get(ti, "MdmComplianceUrl")) : null);

            string intune = null;
            foreach (string id in reg.SubKeys(Collector.Enrollments))
            {
                RegValue p = reg.Get(Collector.Enrollments + "\\" + id, "ProviderID");
                if (p != null && string.Equals(p.Data, "MS DM Server", StringComparison.OrdinalIgnoreCase)) { intune = id; break; }
            }
            if (intune == null)
            {
                d.Add(GMdm, "Intune enrollment", "Not found");
                return;
            }
            string ep = Collector.Enrollments + "\\" + intune;
            d.Add(GMdm, "Intune enrollment", intune);
            d.Add(GMdm, "Enrolled user", Str(reg.Get(ep, "UPN")));
            d.Add(GMdm, "Intune device ID", Str(reg.Get(ep + @"\DMClient\MS DM Server", "EntDMID")));
            string conn = OmaDm + "\\" + intune + @"\Protected\ConnInfo";
            d.Add(GMdm, "Last successful sync", SyncTime(reg.Get(conn, "ServerLastSuccessTime")));
            d.Add(GMdm, "Last sync attempt", SyncTime(reg.Get(conn, "ServerLastAccessTime")));
        }

        // Seen as text such as 20251223T072908Z (UTC). Binary FILETIME is also accepted. Anything else is shown as it is.
        public static string SyncTime(RegValue v)
        {
            if (v == null || string.IsNullOrEmpty(v.Data)) return null;
            string s = v.Data.Trim();
            DateTime t;
            if (DateTime.TryParseExact(s, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                return t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            if (v.Kind == "REG_BINARY" || v.Kind == "REG_QWORD")
            {
                long ft = 0;
                bool ok = false;
                if (v.Kind == "REG_QWORD") ok = long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out ft);
                else
                {
                    string[] hex = s.Split(' ');
                    if (hex.Length == 8)
                    {
                        ok = true;
                        for (int i = 7; i >= 0; i--)
                        {
                            byte x;
                            if (!byte.TryParse(hex[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out x)) { ok = false; break; }
                            ft = (ft << 8) | x;
                        }
                    }
                }
                if (ok && ft > 0)
                {
                    try { return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC"; }
                    catch (ArgumentOutOfRangeException) { }
                }
            }
            return s;
        }

        static void ConfigMgr(IRegSource reg, DeviceInfo d)
        {
            string version = Str(reg.Get(SmsClient, "ProductVersion"));
            d.Add(GConfigMgr, "Client", string.IsNullOrEmpty(version) ? "Not found" : "Installed");
            d.Add(GConfigMgr, "Client version", version);
            d.Add(GConfigMgr, "Site code", Str(reg.Get(SmsClient, "AssignedSiteCode")));
            string flags = Str(reg.Get(Ccm, "CoManagementFlags"));
            if (!string.IsNullOrEmpty(flags))
                d.Add(GConfigMgr, "Co-management", flags == "0" ? "Not configured (flags 0)" : "Configured (flags " + flags + ")");
        }

        static string Str(RegValue v)
        {
            return v == null || string.IsNullOrEmpty(v.Data) ? null : v.Data;
        }
    }
}
