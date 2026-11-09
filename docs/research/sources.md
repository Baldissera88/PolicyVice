# Data sources: what is verified

This file lists every location PolicyVice reads, what each one is for, and the source that confirms it. Each item is marked:

- **Documented**: Microsoft documents it.
- **Observed**: well-known community authors show it on real devices, but Microsoft does not document it.
- **Not verified**: PolicyVice does not depend on it, or treats it with care. Check it on a real device.

Research date: 8 November 2026.

## PolicyManager

### current and providers

| What | Status | Source |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>` holds the resulting MDM value per setting | Observed | [Kenneth van Surksum](https://vansurksum.com/2021/05/25/mdm-policy-processing-on-windows-10-with-microsoft-endpoint-manager-a-closer-look/), [EndpointWeekly](https://endpointweekly.com/blog/intune-update-ring-succeeded-policymanager-registry-effective-policy.html), [Anoop C Nair](https://www.anoopcnair.com/windows-10-intune-mdm-support-help-1/) |
| `current\<UserSID>\<Area>` for user settings | Observed | [Anoop C Nair, tattooing](https://www.anoopcnair.com/intune-policy-tattooed-not-tattooed-windows-csp/) (path `current\S-1-5-21-...\ADMX_ControlPanel`), [Micke-K IntuneManagement](https://github.com/Micke-K/IntuneManagement/blob/master/ADMXImport.md) |
| `providers\<GUID>\default\Device\<Area>` holds what each provider sent; `default\<SID>` for users | Observed | [Michael Niehaus export](https://oofhours.com/2021/10/27/customize-the-windows-11-start-menu/), [Anoop C Nair, Edge](https://www.anoopcnair.com/microsoft-edge-security-policy-deploy-intune/), [fleetdm issue](https://github.com/fleetdm/fleet/issues/38985) |
| The provider GUID is the enrollment ID under `HKLM\SOFTWARE\Microsoft\Enrollments` | Observed | The same GUID appears as "EnrollmentID requesting merge" in event 813 and as the providers key ([Anoop C Nair](https://www.anoopcnair.com/intune-policy-tattooed-not-tattooed-windows-csp/)); [EndpointWeekly](https://endpointweekly.com/blog/intune-update-ring-succeeded-policymanager-registry-effective-policy.html) resolves `_WinningProvider` against Enrollments |
| Not every provider is an MDM enrollment | Observed | EndpointWeekly counts 25 providers on one device, and an update management enrollment owns some Update values |
| The CSP URI is `./Device/Vendor/MSFT/Policy/Config/<Area>/<Policy>` (`./User/...` for users) | Documented | [Understanding ADMX-backed policies](https://learn.microsoft.com/windows/client-management/mdm/understanding-admx-backed-policies) |

**What PolicyVice does:** it reads `current`, looks up each setting in every `providers\<GUID>\default\<scope>\<Area>`, and resolves the provider GUID against Enrollments. A provider GUID that is not an enrollment is shown as **Unknown** (with the GUID), not as Other MDM. A setting that no provider holds gets the **Orphan** finding, unless a providers key could not be read. In that case orphans are not reported and a note says why.

### Companion values

All of these are skipped as settings.

| Suffix | Meaning | Status | Source |
|---|---|---|---|
| `_ProviderSet` | 1 while a provider asserts the setting | Observed | Niehaus export, [EndpointWeekly](https://endpointweekly.com/blog/intune-update-ring-succeeded-policymanager-registry-effective-policy.html), Anoop C Nair (`MDMWinsOverGP_ProviderSet`) |
| `_WinningProvider` | GUID of the provider whose value won | Observed | van Surksum, Niehaus export, fleetdm |
| `_LastWrite` | Present once written; seen under `providers` and under `current` | Observed | Niehaus export (providers), EndpointWeekly (current) |
| `_ADMXInstanceData` | Next to ADMX-backed settings | Observed | [Rudy Ooms](https://call4cloud.nl/2021/07/device-control-removable-storage), [EndpointWeekly](https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html) |

Microsoft does not publish this convention. EndpointWeekly says so and calls it "observed, not documented". Other suffixes may exist.

Windows Hello for Business does not write to PolicyManager. It writes to `HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies` ([EndpointWeekly](https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html)). PolicyVice does not read that yet.

### ADMX-backed and ingested ADMX values

| What | Status | Source |
|---|---|---|
| The value is `<enabled/>`, `<disabled/>`, or `<enabled/><data id="..." value="..."/>`. multiText and list values are separated by U+F000 | Documented | [Understanding ADMX-backed policies](https://learn.microsoft.com/windows/client-management/mdm/understanding-admx-backed-policies) |
| Ingestion URI: `./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/<App>/<Policy\|Preference>/<FileUid>`. Setting URI: `./Device/Vendor/MSFT/Policy/Config/<App>~<Policy\|Preference>~<CategoryPath>/<Policy>` | Observed | [Peter van der Woude](https://petervanderwoude.nl/post/deep-dive-ingesting-third-party-admx-files/) |
| `PolicyManager\AdmxInstalled\<ProviderGUID>\<App>\<Policy\|Preference>\<FileUid>`, with one key per ingested file | Observed | [Micke-K](https://github.com/Micke-K/IntuneManagement/blob/master/ADMXImport.md), [Rudy Ooms](https://call4cloud.nl/2021/07/65000-days-of-night/) |
| `PolicyManager\AdmxDefault` holds the categories from the ADMX | Observed | Micke-K, [Camille Debay](https://static-debay-blog.pages.dev/2019/05/22/deep-dive-admx-ingestion-on-windows-10) |
| Ingested files are stored on disk in `%ProgramData%\Microsoft\PolicyManager\ADMXIngestion\<GUID>\<App>...` | Observed | [Rudy Ooms](https://call4cloud.nl/2021/07/65000-days-of-night/), [Rudy Ooms, Patch My PC](https://patchmypc.com/blog/intune-settings-catalog-error-code-65000/), Micke-K |
| Ingested ADMX may not write to System, Software\Microsoft or Software\Policies\Microsoft, with documented exceptions | Observed | Peter van der Woude |

**Not verified:** the value names inside an `AdmxInstalled\...\<FileUid>` key. Micke-K says it holds the time added, the status and the policy count, but gives no names. PolicyVice lists the keys and does not read those values. Debay (2019) saw files under `C:\Windows\System32\config\systemprofile\AppData\Local\PolicyManager\` on an older build.

### ControlPolicyConflict/MDMWinsOverGP

| What | Status | Source |
|---|---|---|
| URI `./Device/Vendor/MSFT/Policy/Config/ControlPolicyConflict/MDMWinsOverGP`. Device scope only. 1 = MDM wins | Documented | [Policy CSP - ControlPolicyConflict](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict) |
| It applies **only to policies in Policy CSP** that have an equivalent Group Policy, not to other CSPs such as the Defender CSP | Documented | same page |
| For Windows Update, Microsoft recommends `Update/IgnoreWindowsUpdateGroupPolicies` (Windows 11 24H2 with KB5101684 and later) | Documented | same page, [Policy CSP - Update](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update) |
| It lands in `current\device\ControlPolicyConflict` with `MDMWinsOverGP` and `MDMWinsOverGP_ProviderSet` | Observed | [Anoop C Nair](https://www.anoopcnair.com/mdm-wins-over-gpo-group-policy-intune-policy/) |
| It does not work for ingested ADMX such as Edge | Observed, one source | Anoop C Nair |

**What PolicyVice says:**

- For Policy CSP conflicts: "MDMWinsOverGP is on. It blocks the Group Policy value only for Policy CSP settings that have an equivalent Group Policy." When it is off: "there is no guarantee which one wins".
- For ingested ADMX: Microsoft documents MDMWinsOverGP for Policy CSP settings only.
- For the Update area: it names IgnoreWindowsUpdateGroupPolicies and reads it from `current\device\Update`.
- For user settings: MDMWinsOverGP is a device setting, and Microsoft does not document whether it covers user settings.

## Enrollments

| What | Status | Source |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>` with `ProviderID`, `UPN`, `EnrollmentType`, `EnrollmentState`, `DiscoveryServiceFullURL` | Observed | [EndpointWeekly](https://endpointweekly.com/blog/intune-update-ring-succeeded-policymanager-registry-effective-policy.html), [Rudy Ooms](https://call4cloud.nl/mdm-only-enrollment-epm-0x8018000b/) |
| Intune is `ProviderID = MS DM Server` | Observed | EndpointWeekly dump, [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1437743/is-mdm-devid-stored-in-any-registry-key-and-how-is) (`DMClient\MS DM Server`) |
| Other MDMs use their own ProviderID, such as `AirWatchMDM` | Observed | [James Chambers](https://jamesachambers.com/disabling-sccm-mdm-coexistence-mode-unofficial-imperfect-workaround/) |
| MMP-C (EPM, declared configuration) is a second enrollment named `MicrosoftManagementPlatformCloud` | Observed | [Jannik Reinhard](https://jannikreinhard.com/intune-troubleshooting-guide/), [Rudy Ooms](https://call4cloud.nl/in-the-name-of-mmp-c/) |
| Subkeys that are not enrollments have no ProviderID and are skipped | Observed | [JumpCloud ADMU](https://www.powershellgallery.com/packages/JumpCloud.ADMU/2.12.2/Content/Powershell%5CPrivate%5CWindowsMDM%5CGet-WindowsMDMProvider.ps1) filters to GUID keys that have ProviderID |
| Intune device ID is `EntDMID` in `Enrollments\<GUID>\DMClient\MS DM Server` | Observed | Microsoft Q&A, answer by Microsoft staff with Rudy Ooms; [DMClient CSP](https://learn.microsoft.com/windows/client-management/mdm/dmclient-csp) documents EntDMID as "the unique enterprise device ID" set by the server |

**Not verified:** what the EnrollmentType numbers mean. Rudy Ooms gives 6 for an MDM enrollment with the device token during Entra join, 0 for MDM-only/user, and 14 for local MDM. EndpointWeekly saw 32 for an update management enrollment. None of this is documented, so PolicyVice shows the number only. EnrollmentState meanings are also not documented.

**Co-management** shows in Enrollments as the normal Intune enrollment (`MS DM Server`). The Configuration Manager side is read from the client registry (see below).

## Group Policy: Resultant Set of Policy (WMI)

| What | Status | Source |
|---|---|---|
| `RSOP_RegistryPolicySetting` in `root\RSOP\Computer` and `root\RSOP\User`, with `registryKey`, `valueName`, `valueType`, `value` (uint8[]), `deleted`, `command`, `precedence`, `GPOID`, `SOMID`, `id` | Documented | [RSOP_RegistryPolicySetting](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting) |
| `precedence = 1` is the winning setting; higher values lost a conflict | Documented | [RSOP_PolicySetting](https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/policy/rsop-policysetting) |
| `RSOP_GPO` with `id`, `guidName`, `name` | Documented | [RSOP_GPO](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/Policy/rsop-gpo) |
| `GPOID` and `RSOP_GPO.id` hold the same string: `LocalGPO`, or `CN={GUID},CN=Policies,CN=System,DC=...` | Observed | [wutils RSOP_GPO instances](https://wutils.com/wmi/root/rsop/computer/rsop_gpo/instances.html), [wutils RSOP_RegistryPolicySetting instances](https://wutils.com/wmi/root/rsop/computer/rsop_registrypolicysetting/instances.html) |
| `registryKey` is relative, for example `Software\Policies\Microsoft\...`, and `valueName` can be empty for a key entry | Observed | wutils instances |
| `valueType` uses the registry type numbers (1 REG_SZ, 2 EXPAND_SZ, 3 BINARY, 4 DWORD, 7 MULTI_SZ, 11 QWORD) | Documented | [MS-GPREG 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5) (registry.pol types) |
| The user namespace is `root\RSOP\User\<SID with every - replaced by _>` | Observed | [PowerShell Magazine](https://powershellmagazine.com/2013/04/02/pstip-view-policy-settings-with-rsop-wmi-classes/), [Brian Hehir](http://brianhehir.blogspot.com/2009/07/rsop-through-wmi.html), [wutils](https://wutils.com/wmi/root/rsop/user/s_1_5_21_4251975986_251742880_3643873951_500/default.html) |
| Reading it needs an elevated process | Observed | PowerShell Magazine, [gfisk](https://www.gfisk.com/rsop-gpresult-for-target-user-and-computer-with-non-admin-account/) |
| `EnumerationOptions.Timeout` applies to walking the result collection; `ReturnImmediately` makes the call return at once | Documented | [EnumerationOptions](https://learn.microsoft.com/en-us/dotnet/api/system.management.enumerationoptions) |

**What PolicyVice does:**

- Each query uses a 20 second WMI timeout for the connection and the enumeration.
- The whole read runs on a background thread that it waits 45 seconds for.
- If WMI hangs, the remaining RSoP queries are skipped and a note says so.
- User Group Policy is read only for users whose `Policies` key has values.
- When the user namespace does not exist (Group Policy never ran for that user), user values stay **Unknown**, with that reason.
- Values starting with `**` (registry.pol directives) and deleted entries are ignored.

## MDM event log

Channel `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin` ([Collect MDM logs](https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs)). The manifest has no message strings for these events, so the parser does not rely on the text alone. The event data fields come from the 1803 manifest in [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider.xml).

| Event | Level | Data fields (1803) | Message seen | Source |
|---|---|---|---|---|
| 404 | Error | Message1, Message2, Message3, InternalCmdType, Message5, HexInt1 | `MDM ConfigurationManager: Command failure status. Configuration Source ID: (<GUID>), Enrollment Name: (MDMDeviceWithAAD), Provider Name: (Policy), Command Type: (Add: from Replace or Add), CSP URI: (./Device/Vendor/MSFT/...), Result: (The parameter is incorrect.).` | [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1779285/intune-mdm-configurationmanager-command-failure-st), [Anoop C Nair](https://www.anoopcnair.com/intune-logs-event-ids-ime-logs-troubleshooting/) |
| 454 | Error | same as 404 | Same text. An older build showed `Configuraton Source ID: {GUID}, Enrollment Type: FamilySafety, CSP Name: AppLocker, ..., Result: ./Vendor/MSFT/AppLocker/...` without brackets | [windowsphoneinfo](https://www.windowsphoneinfo.com/threads/constantly-getting-mdm-configuration-manager-error-in-event-manager-about-family-safety.283598/), [Micke-K](https://github.com/Micke-K/IntuneManagement/blob/master/ADMXImport.md) |
| 809 | Error | Message1-4, HexInt1-5 | `MDM PolicyManager: Set policy int, Policy: (AllowTelemetry), Area: (System), EnrollmentID requesting set: (<GUID>), Current User: (Device), Int: (0x2AFE388), Enrollment Type: (0x6), Scope: (0x0), Result:(0x86000011) Unknown Win32 Error code: 0x86000011.` | [Mindcore](https://blog.mindcore.dk/2021/11/microsoft-intune-mdm-policymanager/), [inthecloud247](https://inthecloud247.com/mdm-policymanager-per-user-policy-device-wide-scope-specified/) |
| 813 / 814 | Information | | `MDM PolicyManager: Set policy int` / `Set policy string, Policy: (...), Area: (...), EnrollmentID requesting merge: (<GUID>), Current User: (Device), ...` | [Anoop C Nair](https://www.anoopcnair.com/web-sign-in-policy-for-windows-using-intune/) |
| 819 | Information | | Policy deleted | Micke-K, Anoop C Nair |
| 2545 | Error | Message1, Message2, HRESULT | `MDM Declared Configuration: Function (checkNewInstanceData) operation (Read isNewInstanceData) failed with (The parameter is incorrect.)` with `HRESULT = 0x80070057` | [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1068073/event-2545-34microsoft-windows-devicemanagement-en-1.html) |

**What the parser does:**

- It takes `CSP URI: (...)` first. Without it, it takes any `./[Device/|User/]Vendor/MSFT/...` in the message or the event data. URIs can be lowercase.
- It takes `Result: (...)`, which may be text or an HRESULT. Without that label, it takes only a failure HRESULT (0x8xxxxxxx and above), so that a value such as `0x00000002` (the command type) is not taken.
- When the result is text and the event data has an HRESULT, the code is added, as in "The parameter is incorrect. (0x80070057)".
- For PolicyManager events (809 and the like), it reads `Policy: (...)`, `Area: (...)` and `Current User: (Device|SID)`.
- When the message template is missing, LiveEvents keeps the event data in template order and joins it as the message.
- Reading stops at 5000 events, within the chosen number of days, with a note.

The 404 `./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/.../FakePolicy/Version` error ("The system cannot find the file specified.") is common on healthy devices. A Microsoft MVP calls it safe to ignore, but Microsoft has not said so. Its URI does not match a setting, so it adds no finding.

**HRESULTs:** `0x87D1FDE8` (Intune 65000, "Remediation failed") and the `0x87D1xxxx` SyncML codes are Intune reporting codes, listed in [this summary](https://dev.to/adminpackstudio/intune-configuration-profile-error-65000-or-conflict-a-read-first-per-setting-status-and-mdm-event-3707). They normally show in the Intune portal, not in this event log. The parser accepts any 0x8xxxxxxx code.

**Not verified:**

- Which data field holds the CSP URI and result in the Windows 11 manifest. The field order above comes from build 17134, so the parser does not depend on it.
- The levels of 813 and 814.

## Device information

| Item | Location | Status | Source |
|---|---|---|---|
| Domain or workgroup | `NetGetJoinInformation` (0 unknown, 1 unjoined, 2 workgroup, 3 domain) | Documented | [NetGetJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation) |
| Entra join, tenant ID and name, device ID, MDM URLs, join user | `NetGetAadJoinInformation(NULL)` returns DSREG_JOIN_INFO; joinType 1 = Entra joined, 2 = registered (a work account added by the current user) | Documented | [NetGetAadJoinInformation](https://learn.microsoft.com/en-us/windows/desktop/api/lmjoin/nf-lmjoin-netgetaadjoininformation), [DSREG_JOIN_INFO](https://learn.microsoft.com/en-us/windows/desktop/api/lmjoin/ns-lmjoin-dsreg_join_info), [DSREG_JOIN_TYPE](https://learn.microsoft.com/en-us/windows/desktop/api/lmjoin/ne-lmjoin-dsreg_join_type) |
| Join type names (Entra joined, hybrid = Entra joined and domain joined, domain joined; registered is per user) | | Documented | [dsregcmd](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd) |
| Registry fallback: `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\<cert thumbprint>` with `TenantId`, `UserEmail`, `IdpDomain` | | Observed | [AADInternals](https://aadinternals.com/post/deviceidentity/), [EndpointWeekly](https://endpointweekly.com/blog/whfb-dsregcmd-status-reference.html), [Nerdy Mishka](https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/) |
| `CloudDomainJoin\TenantInfo\<TenantId>` with `MdmEnrollmentUrl`, `MdmComplianceUrl`, `MdmTermsOfUseUrl` | | Observed | [Rudy Ooms](https://call4cloud.nl/0x80180031-mobile-device-management/), [j0eyv](https://github.com/j0eyv/AVD-Hybrid-ForceEnrollment/blob/main/ForceEnrollment.ps1) |
| MDM URLs do not prove that the device is enrolled | | Documented | dsregcmd page |
| Last MDM sync: `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\<enrollment ID>\Protected\ConnInfo`, `ServerLastSuccessTime` and `ServerLastAccessTime` | | Observed | [Michael Niehaus](https://oofhours.com/2024/03/30/when-does-a-windows-client-sync-with-intune/), [IntuneToFleetMDM](https://www.powershellgallery.com/packages/IntuneToFleetMDM/0.4.0/Content/Private/MDM/Get-ITFOMADMConnInfo.ps1), [BigFix forum](https://forum.bigfix.com/t/getting-error-codes-from-registry-decimal-output-consistent-conversion-to-hex-only-works-sometimes/49077) |
| Windows: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` `ProductName`, `EditionID`, `DisplayVersion`, `CurrentBuild`, `UBR`. ProductName still says Windows 10 on Windows 11, so build 22000 and later is named Windows 11 | | Observed | [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/555857/windows-11-product-name-in-registry) |
| Configuration Manager client: `HKLM\SOFTWARE\Microsoft\SMS\Mobile Client` `ProductVersion` and `AssignedSiteCode` | | Observed | [Eswar Koneti](https://eskonr.com/2019/12/using-intune-to-install-configmgr-client-as-win32-app-with-local-source-files-without-downloading-from-cmg/), [Prajwal Desai](https://www.prajwaldesai.com/failed-to-read-assigned-site-code-from-registry-error-code-0x80070002/) |
| Co-management flags: `HKLM\SOFTWARE\Microsoft\CCM` `CoManagementFlags` | | Observed | [Ben Whitmore](https://byteben.com/bb/co-management-series-merging-the-perimeter-part-7-co-management-capabilities/). Values per workload since ConfigMgr 2111 ([MSEndpointMgr](https://msendpointmgr.com/2023/02/04/co-management-workloads-capabilities/)), e.g. 8193 is the default co-management value. PolicyVice shows the raw number only |

The last sync time has two observed formats:

- Two independent sources show text such as `20251223T072908Z` (UTC).
- One blog says REG_BINARY FILETIME, without showing a value.

PolicyVice reads both and shows anything else as it is.

The join APIs are called only with the live registry, so tests and the demo never read the real device. On a non-Windows system they fail safely, and the registry is used instead.

## Registry reading

`LiveRegistry` opens each hive once in the 64-bit view, keeps the last opened key, and records access denied per key. Nothing is written. Each source in `Collector.Collect` runs on its own, and a failure becomes a note in `Snapshot.Notes` and in the "Collection" group of the device information.

## Check on the real device

1. **PolicyManager suffixes.** In `current\device\<Area>`, look for value names that end in something other than `_ProviderSet`, `_WinningProvider`, `_LastWrite` or `_ADMXInstanceData`. If any show up as settings in PolicyVice, add them to `Collector.Suffixes`.
2. **Providers.** Check that the Intune enrollment ID equals the `providers\<GUID>` key and the `_WinningProvider` values. Count the providers that are not enrollments. They now show as Unknown.
3. **Orphans.** Pick an Orphan and confirm that no `providers\*\default\Device\<Area>` key has the value.
4. **RSoP elevated.** Check that `root\RSOP\Computer` exists on an Entra-joined device without domain GPOs (local policy only). If it does not, every HKLM Policies value stays Unknown, which is correct but not useful.
5. **User RSoP.** Running elevated as the signed-in user, is `root\RSOP\User\<SID_with_underscores>` there for the Entra user (`S-1-12-1-...`)? On a cloud-only device there may be no user namespace. The note should then say so.
6. **RSoP speed.** Time the RSoP read. If it is slow, lower `LiveRsop.QueryTimeout`.
7. **Events.** Compare a few 404, 454 and 809 events in Event Viewer with the MDM events tab: CSP URI, area/name and result. Check that the Result column is not a command type.
8. **Join info.** Compare the Device tab with `dsregcmd /status`: join type, TenantId, TenantName, DeviceId, MdmUrl, MdmComplianceUrl.
9. **Intune device ID.** Compare EntDMID with the device ID in the Intune admin center.
10. **Last sync.** Check the type and format of `ServerLastSuccessTime`, and compare with Settings > Accounts > Access work or school > Info.
11. **ConfigMgr.** On a co-managed device, check `SMS\Mobile Client` and `CCM\CoManagementFlags`.
12. **Not elevated.** Run once without elevation. Denied keys should appear in the Access denied tab, with no false Orphan or Unmanaged findings.
