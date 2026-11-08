namespace PolicyVice
{
    using System.Collections.Generic;
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

    // Reads join state, tenant and MDM details. Read-only.
    public static class DeviceCollector
    {
        public static DeviceInfo Collect(IRegSource reg)
        {
            return new DeviceInfo();
        }
    }
}
