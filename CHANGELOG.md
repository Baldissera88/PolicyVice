# Changelog

## PolicyVice 0.2.0

9 November 2026.

### New

- **Intune apps and scripts** tab: Win32 apps, platform scripts and remediations from the Intune Management Extension, with status, assignment, error code and meaning, and app names from the IME logs
- **Device** tab: join type, tenant, Entra and Intune device IDs, last sync, MDM URLs, Configuration Manager client and co-management
- **Policy CSP catalog** built in, from Microsoft's documentation: names, descriptions and value meanings for about 3,100 settings, such as `5 (Turn off automatic updates)`, and each setting's Group Policy counterpart
- Exact conflict detection through the ADMX policy or the documented registry value, for every documented Policy CSP setting
- User Group Policy from Resultant Set of Policy, so user policy values show their GPO
- **Sync** button that starts Windows' MDM sync task, and an option to start Watch after a sync
- Settings and About windows, F1 and Ctrl+, shortcuts
- Copy cell, row or all rows from every grid, and Ctrl+C
- HTML report with Device and Intune apps and scripts sections; CSV with the value meaning and Group Policy counterpart

### Fixed and improved

- Every registry, Group Policy and event source is checked against Microsoft's documentation and community sources (see `docs/research`)
- Conflict notes say exactly what Microsoft documents about `MDMWinsOverGP` and `IgnoreWindowsUpdateGroupPolicies`
- A source that fails or times out no longer stops the rest; reading Group Policy can no longer hang the app
- A winning provider that is not an MDM enrollment shows as Unknown instead of Other MDM
- No Orphan findings when a provider key could not be read
- More MDM event formats are parsed, including events without a message text
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
