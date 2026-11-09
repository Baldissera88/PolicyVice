# Testing PolicyVice on a real device

PolicyVice has only run with sample data so far. This checklist compares what it shows with Windows' own tools on a real device. Use an Intune-enrolled Windows 11 PC, ideally one that also gets Group Policy.

Everything PolicyVice does is read-only, except **Sync**, which starts Windows' own MDM sync task.

## Before you start

1. Install `PolicyVice.msi`, or copy `PolicyVice.exe` to a folder that only administrators can change, such as `C:\Program Files\PolicyVice`. A folder like `C:\Temp` can be changed by every user, which is not a good place for a program you run as administrator.
2. Open an elevated PowerShell in a working folder, for example your Documents folder, and collect the reference data:

```powershell
dsregcmd /status > dsregcmd.txt
gpresult /h gpresult.html /f
MdmDiagnosticsTool.exe -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' -zip "$PWD\MDMDiag.zip"
```

`MDMDiagHtmlReport.html` in the zip lists the managed policies and the enrollments that Windows knows about. You get the same report as `MDMDiagReport.html` from **Settings > Accounts > Access work or school > Export your management log files**.

3. Start `PolicyVice.exe` as administrator.

## 1. Start and read

- [ ] The window opens without an error, and the status bar says how many settings were read.
- [ ] Reading takes less than about 30 seconds.
- [ ] The yellow "not running as administrator" bar is not shown.
- [ ] The status bar says "Resultant Set of Policy read". If it shows a note instead, write it down.
- [ ] The **Access denied** tab is empty, or note which keys it lists.

## 2. Enrollments and device

Compare with `dsregcmd.txt`.

- [ ] **Enrollments** shows the Intune enrollment with provider Intune and the right user.
- [ ] On a co-managed device, the Configuration Manager enrollment is shown too.
- [ ] **Device**: join type, tenant ID and name, and device ID match `dsregcmd` (`AzureAdJoined`, `DomainJoined`, `TenantId`, `TenantName`, `DeviceId`).
- [ ] **Device**: the MDM URLs match `MdmUrl` and `MdmComplianceUrl` in `dsregcmd`.

## 3. MDM settings

Compare with the managed policies in the MDM diagnostics report.

- [ ] Click **MDM settings**. The count is close to the number of managed policies in the report.
- [ ] Pick five settings you know from Intune, such as one from Windows Update rings, Defender, a settings catalog profile, an ADMX-backed setting and an ingested ADMX setting like OneDrive. Each one has:
  - [ ] the right value
  - [ ] source **Intune**, with your UPN or the enrollment in the details
  - [ ] a readable name instead of the raw setting name
  - [ ] a value with its meaning, for example `1 (Allowed)`, where the docs define one
- [ ] User-scoped settings, if you have any, show scope **User**.
- [ ] Note any setting with source **Unknown**, and whether you expected it to have an owner.

## 4. Group Policy

Compare with `gpresult.html`.

- [ ] Click **Group Policy values**. The values come from the GPOs in `gpresult`, with the right GPO names.
- [ ] Where two GPOs set the same value, the winning GPO is marked **Wins** in the details.
- [ ] User Group Policy values show the user GPO, not Unknown.

## 5. Findings

- [ ] **Conflicts**: each one is a setting that really is set by both Intune and a GPO. Check one or two in `gpresult` and the Intune portal.
- [ ] **Overlap** in the Findings column is only a hint: a GPO sets something in an area that Intune also configures, such as Windows Update, but not the same setting. It is not counted as a conflict.
- [ ] Values written by Intune ADMX-backed settings, such as a security baseline, device control or OneDrive, show source **MDM (ADMX)**, not Unmanaged.
- [ ] **Settings with errors**: each one matches an error in Event Viewer under *Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin*. A setting that Windows never applied is listed too, with an empty value.
- [ ] The **MDM events** tab shows readable messages, also with Danish regional settings.
- [ ] **Orphans** and **Unmanaged values**: check one of each. Do they make sense, or is PolicyVice wrong about the owner?

## 6. Intune apps and scripts

Compare with the app and script status in the Intune portal, or Company Portal on the device.

- [ ] Win32 apps are listed with the right status. A failed app shows its error code and meaning.
- [ ] App names are shown, not only IDs. They come from the IME logs, so new apps may still show only an ID.
- [ ] Platform scripts and remediations are listed with the right result.

## 7. Watch, snapshots and compare

- [ ] Press **Snapshot > Save snapshot** and save the file.
- [ ] Press **Watch**, then run `gpupdate /force` or **Sync**. Changes appear on the **Changes** tab, with the MDM events around them. "No setting changed" is also a fine result if nothing changed.
- [ ] To force a visible change, create and remove a test value in an elevated PowerShell while Watch is on:

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\PolicyViceTest' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\PolicyViceTest' -Name 'Test' -Value 1 -Type DWord
Start-Sleep -Seconds 60
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\PolicyViceTest' -Recurse
```

  - [ ] The watch log shows **Added** and then **Removed** for `PolicyViceTest\Test`.
- [ ] **Compare > Compare with a saved snapshot** shows the differences since your snapshot.

## 8. Sync and LogVice

- [ ] **Sync** starts an MDM sync. "Last sync" on the Device tab and in Settings > Accounts > Access work or school is updated.
- [ ] **LogVice > MDM events (Admin)** opens the channel in LogVice.
- [ ] **LogVice > Intune Management Extension log** opens the log in LogVice.

## 9. Exports and the command line

- [ ] **Export > HTML report** opens a readable report with the findings first.
- [ ] **Export > CSV** opens in Excel in columns, with one row per setting. It uses the list separator of your regional format, so `;` with Danish settings.
- [ ] From the command line:

```powershell
$p = Start-Process -FilePath .\PolicyVice.exe -ArgumentList '/report', "$PWD\report.html" -Wait -PassThru
$p.ExitCode
```

  The exit code is 0 when there are no findings and 2 when there are.

## 10. Look and feel

- [ ] **Theme** cycles through System, Light, Dark and Vice, and every tab is readable in each.
- [ ] Nothing is cut off at your display scaling, for example 125% or 150%.
- [ ] The window opens at the same size and place next time.

## What to send back

- Screenshots of anything that looks wrong.
- The text of any error message.
- For a wrong value or owner: the setting name and what the MDM diagnostics report or `gpresult` says instead.

The HTML report and snapshots contain user names, GPO names and tenant details, so check them before you share them.
