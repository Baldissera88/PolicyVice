# Intune Management Extension: where the state lives

Notes behind `src/Ime.cs`. Microsoft does not document the IME registry layout. Most of what follows comes from community tools that read these keys in code, cross-checked where possible. Each statement is marked:

- **Verified (Microsoft)**: stated on learn.microsoft.com.
- **Verified (code)**: read in the source of a published tool that uses it.
- **Reported**: described in an article or log excerpt, not seen in code.
- **Unverified**: an assumption PolicyVice makes. Check it on a real device.

Root key: `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension`. Reading it needs administrator rights. The IntuneStuff module checks for admin before reading it, with the comment that the key "now needs admin permission".

## User keys

| Key name | Meaning | Status |
|---|---|---|
| `00000000-0000-0000-0000-000000000000` | Device (system) context | Verified (code): IntuneStuff `_getTargetName`, IntuneDebug, msendpointmgr |
| `S-0-0-00-0000000000-0000000000-000000000-000` | Device context, older form | Verified (code): IntuneStuff |
| any other GUID | Entra ID object ID of the user | Verified (code): IntuneStuff; Oliver Kieselbach ("matches my Azure AD user object ID") |

PolicyVice shows the device context as `System`, and other users by their object ID. A user SID as a key name is also accepted.

## Win32 apps

Layout: `Win32Apps\<user>\<app ID>_<revision>\`

- **Verified (code).** The app key name is the app GUID plus `_<number>`. IntuneStuff strips `_\d+$` and takes the highest number as the newest record. PolicyVice does the same and lists the older revisions in the detail text.
- **Verified (code).** IntuneStuff skips the `OperationalState` and `Reporting` subkeys of `Win32Apps`, and the `GRS` subkey of each user key. PolicyVice only reads keys whose names are GUIDs or SIDs.
- **Verified (code).** `ComplianceStateMessage` and `EnforcementStateMessage` are subkeys of the app key. Each holds a value of the same name containing JSON (`Get-ItemPropertyValue "$path\ComplianceStateMessage" -Name ComplianceStateMessage`). PolicyVice also accepts them as values on the app key itself.
- **Verified (code).** The app key holds the values `LastUpdatedTimeUtc` and `Intent` (0 dependency, 1 available, 3 required, 4 uninstall). Eswar Koneti's table agrees on 1, 3 and 4.
- **Reported.** The app key also holds `DownloadStartTimeUTC` (call4cloud). PolicyVice uses it as the time only when `LastUpdatedTimeUtc` is missing.

ComplianceStateMessage fields: `Applicability`, `ComplianceState`, `DesiredState`, `ErrorCode`, `TargetingMethod`, `InstallContext`, `TargetType`, `ProductVersion`, `AssignmentFilterIds`. EnforcementStateMessage fields: `EnforcementState`, `ErrorCode`, `TargetingMethod`. **Verified (code)**: Get-Win32AppResult (PowerShell Gallery), IntuneStuff, call4cloud GRS scripts.

The enum values come from Ben Whitmore's article, which took them from the decompiled IME. PolicyVice uses that article's full tables. Eswar Koneti (2019) and IntuneStuff give the same numbers for the subset they list. **Reported** (not Microsoft-documented):

- **ComplianceState:** 1 Installed, 2 NotInstalled, 4 Error, 5 Unknown, 100 Cleanup. Older tables also have 0 Unknown and 3 Conflict.
- **DesiredState:** 0 None, 1 NotPresent, 2 Present, 3 Unknown, 4 Available.
- **Applicability:** 0 Applicable, 1 RequirementsNotMet, 3 HostPlatformNotApplicable, 1000 to 1012 specific requirement failures (1010 AssignmentFiltersCriteriaNotMet), 2000 to 2003 COSU.
- **InstallContext:** 1 User, 2 System. **TargetType:** 0 None, 1 User, 2 Device, 3 Both.
- **EnforcementState:**

| Range | Meaning |
|---|---|
| 1000 to 1018 | Success variants (1000 Success) |
| 2000 to 2012 | In progress (2008 pending reboot, 2009 downloaded) |
| 3000 | Requirements not met |
| 4000 | Unknown |
| 5000 to 5999 | Error (5003 download, 5999 error with immediate retry) |
| 6000 to 6013 | Not attempted (6001 dependency failed, 6002 pending reboot) |

PolicyVice's status logic, in `ImeCollector.AppStatus`:

1. Applicability other than 0 gives "Not applicable".
2. Enforcement 5xxx, or an error code other than 0, 3010 or 1641, gives a failure. The failure is reported as "Waiting for retry" (5999), "Download failed" (5003), "Detection failed" (0x87D1041C), "Uninstall failed" when the desired state is NotPresent, or "Install failed" otherwise.
3. Otherwise the status comes from ComplianceState and EnforcementState together: Installed, "Installed, reboot pending", In progress, Not attempted, and so on.

The same rules are used when calling the 3010 and 1641 return codes a success. **Verified (code)**: the call4cloud GRS detection script treats 0 and 3010 as success.

### GRS (global re-evaluation schedule)

- **Verified (Microsoft):** "Each dependency will adhere to Intune Win32 app retry logic (try to install three times after waiting for five minutes) and the global reevaluation schedule, which follows a 24-hour cadence." A Retry return code makes the agent "attempt to install the app three times. It will wait for five minutes between each attempt." ([Win32 app add](https://learn.microsoft.com/mem/intune/apps/apps-win32-add), updated 2026-04-14)
- **Verified (code):** The GRS key is `Win32Apps\<user>\GRS\<hash>`. IntuneStuff and the call4cloud script delete it to force a retry.
- **Reported:** The hash is a Base64 SHA-256 over app policy fields, not the app ID (alttabtowork.com, 2026-08). The app ID under the hash key holds the last attempt time. The Robopack log excerpt reads `Saved GRS value: 10/01/2026 02:38:27 to path: <user>\GRS\<hash>\<app ID>`. Scripts by Advanced Installer and Anyways Modernize look for a value named after the app ID.
- **Unverified:** whether the app ID under the hash is a value or a subkey. PolicyVice accepts both and reads the first value that parses as a date. When the app has failed, PolicyVice shows the last attempt and "next attempt after about +24 h". That is an estimate.

### Status service reports

- **Verified (code):** `SideCarPolicies\StatusServiceReports\<user>\<entry>` with the values `AppId`, `ApplicabilityCode`, `ApplicabilityCode2`, `CustomError`, `Required`, `Status`, `Status2`, `ErrorCode`. Source: Get-IntuneWin32AppPolicies.ps1 in the IntuneDebug module (Jonas Ohmsen). That code compares `Status` with `Installed` and `ApplicabilityCode` with `Applicable`, so the values are text.
- PolicyVice adds these values to the detail of a matching Win32 app. An app that has a report but no Win32Apps key, for example one whose requirements are not met, becomes its own item.
- **Unverified:** the full set of `Status` texts, and whether the entry key name is the app ID.

## Platform scripts

Layout: `Policies\<user>\<script ID>`

- **Verified (code)** (IntuneStuff `Invoke-IntuneScriptRedeploy`): the values are `Result`, `ErrorCode`, `DownloadCount`, `LastUpdatedTimeUtc`, `RunAsAccount` and `ResultDetails`. `ResultDetails` is JSON whose `ExecutionMsg` holds the script output.
- **Reported:** `Result` is "Success" or "Failed" (Oliver Kieselbach). `DownloadCount` is also the execution count. Resetting `DownloadCount`, `ErrorCode`, `Result` and `ResultDetails` makes the script run again (Kieselbach, pariswells.com).
- **Verified (Microsoft):** "If the script fails, the Intune management extension retries the script three times for the next three consecutive Intune management extension check-ins." After that it does not run again unless the script or policy changes. ([PowerShell scripts](https://learn.microsoft.com/en-us/intune/intune-service/apps/powershell-scripts))
- **Unverified:** the exact `ErrorCode` meaning for scripts. It is probably the PowerShell exit code. PolicyVice shows the number and treats any non-zero value as a failure.

## Remediations

- **Verified (code)** (IntuneStuff `Get-IntuneRemediationScriptLocally`):
  - Results are in `SideCarPolicies\Scripts\Reports\<user>\<policy ID>_<n>\Result`, in a value named `Result` that holds JSON.
  - The last run is in `SideCarPolicies\Scripts\Execution\<user>\<policy ID>_<n>`, in the value `LastExecution`.
  - The user key under Reports has `LastFullReportTimeUTC`.
- **Verified (code + sample):** The Result JSON fields are `PolicyId`, `UserId`, `PolicyHash`, `Result`, `ResultDetails`, `InternalVersion`, `ErrorCode`, `ResultType`, `PreRemediationDetectScriptOutput`, `PreRemediationDetectScriptError`, `RemediationScriptErrorDetails`, `PostRemediationDetectScriptOutput`, `PostRemediationDetectScriptError` and `RemediationStatus`. `Info` holds `RemediationExitCode`, `FirstDetectExitCode`, `LastDetectExitCode` and `ErrorDetails`. Sources: IntuneStuff, and a sample in Peter van der Woude (2020) and Joymalya Basu Roy, both showing `Result:3, ResultType:1, RemediationStatus:4` for "no issue".
- **Reported:** RemediationStatus is 4 when detection exited 0, 1 when remediated and then detected clean, 2 when the post-detection still failed (recurred), and 3 when the remediation exited non-zero or wrote to stderr. This comes from Tech by Jeff, "Running Intune Scripts Locally the Way the Agent Does", 2026-10-07, based on device tests. PolicyVice maps the values to No issue, Issue fixed, Issue recurred and Remediation failed. Without a known status it falls back to the Info exit codes.
- **Verified (Microsoft):** Detection must `exit 1` for an issue, and any other exit code means the remediation does not run. Output is capped at 2,048 characters. ([Remediations](https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations))
- **Verified (Microsoft):** For comparison, the Graph `remediationState` is 0 unknown, 1 skipped, 2 success, 3 remediationFailed, 4 scriptError. This differs from the local `RemediationStatus` numbers, so the two must not be mixed up.
- **Unverified:** the meaning of `Result` and `ResultType`, which are 3 and 1 in every sample seen. PolicyVice shows them raw.

## Names

The registry holds IDs only. All tools that show names either call Graph or read the logs.

| Log line | Source | Status |
|---|---|---|
| `<![LOG[Get policies = [{"Id":"…","Name":"…",…}]]LOG]!>` | IntuneStuff, IntuneDebug (`AppWorkload*.log`), Get-IntuneManagementExtensionDiagnostics | Verified (code) |
| `[Win32App] Sending results to service. session RequestPayload: [{"AppId":"…","ApplicationName":"…",…}]` | IntuneStuff | Verified (code) |
| `[StatusService] Downloading app (id = …, name …) via DO` | Get-IntuneManagementExtensionDiagnostics; Robopack excerpt | Verified (code) |
| `[Win32App] Content cache miss for app (id = …, name = …)` | Robopack excerpt | Reported |
| `[HS] Get policies = [{"AccountId":…,"PolicyId":…}]` | IntuneStuff | Verified (code). No display name for remediations. |

Microsoft documents the log files in the Logs folder: IntuneManagementExtension.log, AppWorkload.log, AgentExecutor.log, HealthScripts.log, AppActionProcessor.log and ClientHealth.log. AppWorkload.log is the main app workload log. ([Win32 troubleshooting](https://learn.microsoft.com/mem/intune/apps/apps-win32-troubleshoot), updated 2026-04-14)

`ImeLog` reads these patterns from the tail of a file (20 MB by default) or a folder (100 MB in all), opened with `FileShare.ReadWrite`. It parses JSON only up to `]LOG]!>`, so a cut-off line does not swallow the next one. Later lines win. Platform scripts and remediations have no name in the logs, so they keep their ID.

## Error codes

Only codes with a Microsoft source are given a meaning.

| Code | Text | Source |
|---|---|---|
| 0x87D1041C | The application was not detected after installation completed successfully. | Microsoft Tech Community "Error codes for troubleshooting app installation issues"; Microsoft Learn training module ("App installed successfully but is no longer detected"); Microsoft Q&A answer: incorrect detection rule |
| 0x87D300C9 | The unmonitored process is in progress, however it may timeout. | Microsoft Q&A, accepted answer by Microsoft staff: Intune stopped monitoring a process that was still running |
| 0x87D30065 | Failed to retrieve content information. | Message text as quoted on Microsoft Q&A. The cause is not confirmed by Microsoft. |
| 0x87D30067 | Error unzipping downloaded content. | Message text as quoted on Microsoft Q&A and Tech Community |
| 0x80070643 | Fatal error during installation (MSI 1603) | Tech Community error code list |
| 0x8000FFFF | Unexpected error during installation | Microsoft Learn training module |
| 1602, 1603, 1618, 1619, 1620, 1625, 1633, 1638, 1639, 1641, 3010 | Windows Installer messages | [MsiExec.exe and InstMsi.exe error messages](https://learn.microsoft.com/en-us/previous-versions/aa368542(v=vs.85)) |

Default return codes are not listed on the current Win32 page, so PolicyVice does not claim them. Only 0, 3010 and 1641 are treated as success. 3010 and 1641 are "indicative of a success" per the MSI page. Other 0x8007xxxx codes get the Windows message text on Windows.

## Check on a real device

1. Win32 apps:
   - [ ] The JSON is in a subkey (`<app>_<n>\ComplianceStateMessage`, value `ComplianceStateMessage`), not a value on the app key.
   - [ ] `LastUpdatedTimeUtc` exists, and its format reads as UTC. The tests assume `MM/dd/yyyy HH:mm:ss`, as in the IME log. If the device writes a local-culture format, the time may be wrong.
   - [ ] `ErrorCode` in the JSON is a signed decimal, such as -2016345060 for 0x87D1041C.
2. GRS: what is under `GRS\<hash>`. Is the app ID a value or a subkey, and is the data a date?
3. `StatusServiceReports`: does it exist on this IME version, what are the entry key names, and what `Status` texts appear?
4. Platform scripts: `Result` texts other than Success and Failed, the `ErrorCode` meaning, and the `RunAsAccount` values.
5. Remediations: a fixed, a recurred and a failing remediation, compared with the admin center status. This tests the RemediationStatus 1 to 4 mapping.
6. Names: run `ImeLog.FillNamesFromFolder` and see how many apps get a name. Apps not processed since the logs rolled over keep their ID.
7. Without admin rights, check that an "IME / Access denied" item appears and nothing throws.

## Sources

- Ben Whitmore, [Win32 app State Messages Demystified](https://msendpointmgr.com/2023/08/28/win32-app-state-messages-demystified/), msendpointmgr.com, 2023-08-28
- Ondrej Sebela, IntuneStuff module, [github.com/ztrhgf/useful_powershell_modules](https://github.com/ztrhgf/useful_powershell_modules). Read files: `Get-IntuneWin32AppLocally.ps1`, `Invoke-IntuneScriptRedeploy.ps1`, `Get-IntuneRemediationScriptLocally.ps1`, `Get-IntuneLogWin32AppData.ps1`, `Get-IntuneLogWin32AppReportingResultData.ps1`, `Get-UserSIDForUserAzureID.ps1`, `Invoke-IntuneWin32AppRedeploy.ps1`. Commit 4b9c624, 2026-10-09.
- Rudy Ooms, [Retry Lola Retry](https://call4cloud.nl/2022/07/retry-lola-retry/) and the GRS [detection](https://call4cloud.nl/wp-content/uploads/2022/07/grsdetection.txt) and [remediation](https://call4cloud.nl/wp-content/uploads/2022/07/grsremediation.txt) scripts
- Jonas Ohmsen, [IntuneDebug](https://www.powershellgallery.com/packages/IntuneDebug/4.0.1), `Get-IntuneWin32AppPolicies.ps1` and `Get-IntuneScriptPolicies.ps1`
- [Get-Win32AppResult](https://www.powershellgallery.com/packages/Get-Win32AppResult/1.0.2/Content/Get-Win32AppResult.ps1), PowerShell Gallery
- [Get-IntuneManagementExtensionDiagnostics 2.3](https://www.powershellgallery.com/packages/Get-IntuneManagementExtensionDiagnostics/2.3/Content/Get-IntuneManagementExtensionDiagnostics.ps1)
- Oliver Kieselbach, Deep dive Microsoft Intune Management Extension, [PowerShell scripts part 2](https://oliverkieselbach.com/2018/02/12/part-2-deep-dive-microsoft-intune-management-extension-powershell-scripts/) and [Win32 apps part 3](https://oliverkieselbach.com/2018/10/02/part-3-deep-dive-microsoft-intune-management-extension-win32-apps/)
- Peter van der Woude, [Detecting local administrators with proactive remediations](https://petervanderwoude.nl/post/detecting-local-administrators-with-proactive-remediations/), 2020
- Eswar Koneti, [Status codes deep dive](https://eskonr.com/2019/11/status-codes-deep-dive-troubleshooting-win32-app-deployment/), 2019
- Tech by Jeff, [Running Intune Scripts Locally the Way the Agent Does](https://www.techbyjeff.net/running-intune-scripts-locally-the-way-the-agent-does/) and [Reading the IME logs as objects](https://www.techbyjeff.net/reading-the-intune-management-extension-logs-as-objects/), 2026-10
- Hailey Phillips, [A Deep Dive into Intune Win32 App Deployment](https://robopack.com/blog/intune-win32-app-deployment/), Robopack, 2026-10-12
- Haakon, [Decoding the Intune Win32 App GRS Hash](https://alttabtowork.com/2026/08/06/decoding-the-intune-win32-app-grs-hash/), 2026-08-06
- Microsoft Learn:
  - [Win32 app add](https://learn.microsoft.com/mem/intune/apps/apps-win32-add)
  - [Win32 troubleshooting](https://learn.microsoft.com/mem/intune/apps/apps-win32-troubleshoot)
  - [PowerShell scripts](https://learn.microsoft.com/en-us/intune/intune-service/apps/powershell-scripts)
  - [Remediations](https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations)
  - Graph [remediationState](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-remediationstate?view=graph-rest-beta) and [runState](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-runstate?view=graph-rest-beta)
  - [MSI error messages](https://learn.microsoft.com/en-us/previous-versions/aa368542(v=vs.85))
  - [App deployment failures training module](https://learn.microsoft.com/en-us/training/modules/deploy-manage-applications-intune/11-manage-app-deployment-failures-logs-troubleshooting)
- Microsoft Q&A: [0x87D1041C](https://learn.microsoft.com/en-us/answers/questions/2134779/the-application-was-not-detected-after-the-install), [0x87D300C9](https://learn.microsoft.com/en-us/answers/questions/2105540/the-unmonitored-process-is-in-progress-however-it), [0x87D30065](https://learn.microsoft.com/en-us/answers/questions/5780882/failed-to-retrieve-content-information-(0x87d30065)
- Microsoft Tech Community, [Error codes for troubleshooting app installation issues](https://techcommunity.microsoft.com/blog/intunecustomersuccess/error-codes-for-troubleshooting-app-installation-issues/280113)
