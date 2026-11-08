namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.Serialization;

    // One Win32 app, platform script or remediation known to the Intune Management Extension.
    [DataContract]
    public sealed class ImeItem
    {
        [DataMember] public string Kind;
        [DataMember] public string Id;
        [DataMember] public string Name;
        [DataMember] public string User;
        [DataMember] public string Status;
        [DataMember] public string ErrorCode;
        [DataMember] public DateTime? Time;
        [DataMember] public bool Failed;
        [DataMember] public string Detail;
        [DataMember] public string RegistryPath;
    }

    // Reads the Intune Management Extension state from the registry. Read-only.
    public static class ImeCollector
    {
        public static List<ImeItem> Collect(IRegSource reg)
        {
            return new List<ImeItem>();
        }
    }
}
