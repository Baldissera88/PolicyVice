# Changelog

## PolicyVice 0.3.1

9 November 2026.

- The MSI closes a running PolicyVice before it upgrades or uninstalls, also a copy running as administrator, so the upgrade no longer stalls on files in use and needs no restart


## PolicyVice 0.3.0

9 November 2026. Friendly names instead of IDs and codes.

- **Get names from Intune** on the Intune apps and scripts tab: an optional, read-only sign-in to Microsoft Graph with a device code. It reads the names of apps, platform scripts and remediations, and saves them per tenant on this computer, so they show next time without signing in. The sign-in itself is not saved.
- Sign-in uses the Microsoft Graph Command Line Tools app by default; another client ID can be set in **Settings**, where saved names can also be removed
- User names instead of SIDs and Intune user object IDs, from the enrollments, the Windows sign-in cache and the user profiles
- Readable areas, such as *Terminal Server (ADMX)* and *Office 16: Microsoft Office System > Security Settings*
- ADMX-backed values in words, such as *Enabled, KFM Silent Opt In Box: tenant ID*, instead of `<enabled/><data … />`
- Security options and user rights use their Group Policy names, such as *Interactive logon: Don't display last signed-in*
- The provider of a setting is shown as *Intune · user* instead of the enrollment GUID
- MDM events show the name of the setting they are about


## PolicyVice 0.2.0

9 November 2026.

### New

- **Intune apps and scripts** tab: Win32 apps, platform scripts and remediations from the Intune Management Extension, with status, assignment, error code and meaning, and app names from the IME logs
- **Device** tab: join type, tenant, Entra and Intune device IDs, last sync, MDM URLs, Configuration Manager client and co-management
- **Policy CSP catalog** built in, from Microsoft's documentation: names, descriptions and value meanings for about 3,100 settings, such as `5 (Turn off automatic updates)`, and each setting's Group Policy counterpart
- Exact conflict detection through the ADMX policy or the documented registry value, for every documented Policy CSP setting
- User Group Policy from Resultant Set of Policy, so user policy values show their GPO
- **Sync** button that starts Windows' MDM sync task, and an option to start Watch after a sync
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies` is read and watched, with Group Policy and MDM owners, so settings like HideFastUserSwitching are covered
- Values written by ADMX-backed MDM settings, such as security baselines, device control and OneDrive, are attributed to MDM
- Settings that Windows failed to apply are listed with one Error finding each, with the number of failures
- The signed-in user's policy is read when PolicyVice runs as another administrator account
- Settings and About windows, F1 and Ctrl+, shortcuts
- Copy cell, row or all rows from every grid, and Ctrl+C
- HTML report with Device and Intune apps and scripts sections; CSV with the value meaning and Group Policy counterpart

### Fixed and improved

- Every registry, Group Policy and event source is checked against Microsoft's documentation and community sources (see `docs/research`)
- Conflict notes say exactly what Microsoft documents about `MDMWinsOverGP` and `IgnoreWindowsUpdateGroupPolicies`
- A source that fails or times out no longer stops the rest; reading Group Policy can no longer hang the app
- A winning provider that is not an MDM enrollment shows as Unknown instead of Other MDM
- No Orphan findings when a provider key could not be read
- More MDM event formats are parsed, including events without a message text, and messages are read in the Windows display language so they are not empty with Danish regional settings
- Area matches between Group Policy and MDM are now an Overlap hint instead of a Conflict
- The watch log no longer shows changes of source only, and a manual refresh while watching no longer hides changes
- The CSV uses the list separator of the regional format, so it opens in columns in Excel
- Saved reports open in the signed-in user's browser, not as administrator; Windows DLLs load from System32 only
- A refresh requested while reading is queued instead of lost
- Errors in buttons and menus show in the status bar instead of closing the app

## PolicyVice 0.1.0

First version, 8 November 2026.

- Settings view with every MDM setting and every value under `SOFTWARE\Policies`, with source, scope and findings
- Source of each MDM setting from the winning provider and the enrollments, and of each policy value from Resultant Set of Policy or the MDM setting behind it
- Findings: conflicts between MDM and Group Policy, MDM errors from the event log, orphaned MDM values and unmanaged policy values
- Friendly names and descriptions from the ADMX and ADML files on the device and from ingested ADMX
- MDM events, enrollments, ingested ADMX, raw policy registry and access denied views
- Watch mode that records every change to the policy keys with the MDM events around it
- Snapshots as JSON, and comparison with a snapshot or between two snapshots
- HTML report and CSV export
- Open MDM, Intune Management Extension, Group Policy and Entra ID logs in LogVice
- Light, Dark and Vice themes, the same as LogVice
- Command line: `/snapshot`, `/report`, `/csv` and `/diff`
- Demo mode: `PolicyVice.exe --demo`
