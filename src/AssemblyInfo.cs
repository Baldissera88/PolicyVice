using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("PolicyVice")]
[assembly: AssemblyDescription("Policy inspector for Intune, MDM and Group Policy")]
[assembly: AssemblyProduct("PolicyVice")]
[assembly: AssemblyCompany("Daniel L. Baldissera")]
[assembly: AssemblyCopyright("Copyright © 2026 Daniel L. Baldissera")]
[assembly: AssemblyVersion("0.3.2.0")]
[assembly: AssemblyFileVersion("0.3.2.0")]
[assembly: AssemblyInformationalVersion("0.3.2")]
[assembly: ComVisible(false)]
// Load Windows DLLs from System32 only, never from the folder PolicyVice runs from.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.5", FrameworkDisplayName = ".NET Framework 4.5")]
