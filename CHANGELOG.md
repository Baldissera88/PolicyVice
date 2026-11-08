# Changelog

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
