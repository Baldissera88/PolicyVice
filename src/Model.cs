namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Json;
    using System.Text;

    public static class Layers
    {
        public const string Mdm = "MDM";
        public const string Registry = "Registry";
    }

    public static class Sources
    {
        public const string Intune = "Intune";
        public const string OtherMdm = "Other MDM";
        public const string GroupPolicy = "Group Policy";
        public const string MdmAdmx = "MDM (ADMX)";
        public const string Unmanaged = "Unmanaged";
        public const string Unknown = "Unknown";
    }

    public static class FindingKinds
    {
        public const string Conflict = "Conflict";
        public const string Error = "Error";
        public const string Orphan = "Orphan";
        public const string Unmanaged = "Unmanaged";
    }

    [DataContract]
    public sealed class Enrollment
    {
        [DataMember] public string Id;
        [DataMember] public string ProviderId;
        [DataMember] public string Upn;
        [DataMember] public int EnrollmentType;
        [DataMember] public int EnrollmentState;
        [DataMember] public string DiscoveryUrl;

        public bool IsIntune
        {
            get { return string.Equals(ProviderId, "MS DM Server", StringComparison.OrdinalIgnoreCase); }
        }

        public string ProviderName
        {
            get
            {
                if (IsIntune) return "Intune";
                return string.IsNullOrEmpty(ProviderId) ? "Unknown" : ProviderId;
            }
        }
    }

    [DataContract]
    public sealed class Contribution
    {
        [DataMember] public string Source;
        [DataMember] public string Detail;
        [DataMember] public string ProviderId;
        [DataMember] public string Value;
        [DataMember] public string RegistryPath;
        [DataMember] public bool Wins;
    }

    [DataContract]
    public sealed class Finding
    {
        [DataMember] public string Kind;
        [DataMember] public string Message;

        public Finding() { }

        public Finding(string kind, string message)
        {
            Kind = kind;
            Message = message;
        }
    }

    [DataContract]
    public sealed class PolicySetting
    {
        [DataMember] public string Layer;
        [DataMember] public string Scope;
        [DataMember] public string UserSid;
        [DataMember] public string Area;
        [DataMember] public string Name;
        [DataMember] public string FriendlyName;
        [DataMember] public string Value;
        [DataMember] public string ValueKind;
        [DataMember] public string Source;
        [DataMember] public string SourceDetail;
        [DataMember] public string RegistryPath;
        [DataMember] public string CspUri;
        [DataMember] public string Description;
        [DataMember] public string WinningProvider;
        [DataMember] public List<Contribution> Contributions = new List<Contribution>();
        [DataMember] public List<Finding> Findings = new List<Finding>();
        [DataMember] public string ValueMeaning;
        [DataMember] public string GroupPolicyName;
        [DataMember] public string GroupPolicyPath;

        // The value with its documented meaning, such as "1 (Allowed)".
        public string DisplayValue
        {
            get { return string.IsNullOrEmpty(ValueMeaning) ? Value : Value + " (" + ValueMeaning + ")"; }
        }

        public string Key
        {
            get { return Layer + "|" + Scope + "|" + (UserSid ?? "") + "|" + Area + "|" + Name; }
        }

        public string DisplayName
        {
            get { return string.IsNullOrEmpty(FriendlyName) ? Name : FriendlyName; }
        }

        public bool Has(string kind)
        {
            if (Findings == null) return false;
            foreach (Finding f in Findings) if (f.Kind == kind) return true;
            return false;
        }

        public void Add(string kind, string message)
        {
            if (Findings == null) Findings = new List<Finding>();
            foreach (Finding f in Findings) if (f.Kind == kind && f.Message == message) return;
            Findings.Add(new Finding(kind, message));
        }
    }

    [DataContract]
    public sealed class MdmError
    {
        [DataMember] public DateTime Time;
        [DataMember] public int EventId;
        [DataMember] public string Level;
        [DataMember] public string CspUri;
        [DataMember] public string Result;
        [DataMember] public string Message;
        [DataMember] public string Area;
        [DataMember] public string Name;
        [DataMember] public string Scope;
    }

    [DataContract]
    public sealed class RegistryEntry
    {
        [DataMember] public string Path;
        [DataMember] public string Name;
        [DataMember] public string Kind;
        [DataMember] public string Data;
    }

    [DataContract]
    public sealed class AdmxFile
    {
        [DataMember] public string ProviderId;
        [DataMember] public string App;
        [DataMember] public string SettingType;
        [DataMember] public string Id;
        [DataMember] public int Policies;
        [DataMember] public string Origin;
    }

    [DataContract]
    public sealed class Snapshot
    {
        [DataMember] public string Tool = "PolicyVice";
        [DataMember] public string ToolVersion;
        [DataMember] public string Computer;
        [DataMember] public string UserName;
        [DataMember] public string OsVersion;
        [DataMember] public bool Elevated;
        [DataMember] public DateTime TakenUtc;
        [DataMember] public bool MdmWinsOverGp;
        [DataMember] public bool RsopAvailable;
        [DataMember] public string RsopNote;
        [DataMember] public int EventDays;
        [DataMember] public List<Enrollment> Enrollments = new List<Enrollment>();
        [DataMember] public List<PolicySetting> Settings = new List<PolicySetting>();
        [DataMember] public List<MdmError> Errors = new List<MdmError>();
        [DataMember] public List<RegistryEntry> PolicyRegistry = new List<RegistryEntry>();
        [DataMember] public List<AdmxFile> AdmxFiles = new List<AdmxFile>();
        [DataMember] public List<string> AccessDenied = new List<string>();
        [DataMember] public DeviceInfo Device = new DeviceInfo();
        [DataMember] public List<ImeItem> Intune = new List<ImeItem>();

        public int Count(string kind)
        {
            int n = 0;
            foreach (PolicySetting s in Settings) if (s.Has(kind)) n++;
            return n;
        }

        public int CountSource(string source)
        {
            int n = 0;
            foreach (PolicySetting s in Settings) if (s.Source == source) n++;
            return n;
        }

        public int CountLayer(string layer)
        {
            int n = 0;
            foreach (PolicySetting s in Settings) if (s.Layer == layer) n++;
            return n;
        }

        public Enrollment FindEnrollment(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            string k = id.Trim('{', '}');
            foreach (Enrollment e in Enrollments)
                if (string.Equals(e.Id.Trim('{', '}'), k, StringComparison.OrdinalIgnoreCase)) return e;
            return null;
        }

        public void Save(string path)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(Snapshot), Json.Settings());
            using (FileStream fs = File.Create(path))
            {
                ser.WriteObject(fs, this);
            }
        }

        public static Snapshot Load(string path)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(Snapshot), Json.Settings());
            using (FileStream fs = File.OpenRead(path))
            {
                Snapshot s = ser.ReadObject(fs) as Snapshot;
                if (s == null || s.Tool != "PolicyVice") throw new InvalidDataException("This is not a PolicyVice snapshot.");
                if (s.Settings == null) s.Settings = new List<PolicySetting>();
                if (s.Enrollments == null) s.Enrollments = new List<Enrollment>();
                if (s.Errors == null) s.Errors = new List<MdmError>();
                if (s.PolicyRegistry == null) s.PolicyRegistry = new List<RegistryEntry>();
                if (s.AdmxFiles == null) s.AdmxFiles = new List<AdmxFile>();
                if (s.AccessDenied == null) s.AccessDenied = new List<string>();
                if (s.Device == null) s.Device = new DeviceInfo();
                if (s.Device.Items == null) s.Device.Items = new List<InfoItem>();
                if (s.Intune == null) s.Intune = new List<ImeItem>();
                foreach (PolicySetting p in s.Settings)
                {
                    if (p.Findings == null) p.Findings = new List<Finding>();
                    if (p.Contributions == null) p.Contributions = new List<Contribution>();
                }
                return s;
            }
        }
    }

    static class Json
    {
        public static DataContractJsonSerializerSettings Settings()
        {
            DataContractJsonSerializerSettings s = new DataContractJsonSerializerSettings();
            s.DateTimeFormat = new DateTimeFormat("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffK");
            s.UseSimpleDictionaryFormat = true;
            return s;
        }
    }

    public static class Txt
    {
        public static string SplitCamel(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            StringBuilder b = new StringBuilder(s.Length + 8);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '_') { b.Append(' '); continue; }
                if (i > 0 && char.IsUpper(c))
                {
                    char p = s[i - 1];
                    bool nextLower = i + 1 < s.Length && char.IsLower(s[i + 1]);
                    if (char.IsLower(p) || char.IsDigit(p) || (char.IsUpper(p) && nextLower)) b.Append(' ');
                }
                b.Append(c);
            }
            return b.ToString().Replace("  ", " ").Trim();
        }

        public static string Short(string s, int max)
        {
            if (s == null) return "";
            s = s.Replace("\r", " ").Replace("\n", " ");
            return s.Length <= max ? s : s.Substring(0, Math.Max(0, max - 1)) + "…";
        }
    }
}
