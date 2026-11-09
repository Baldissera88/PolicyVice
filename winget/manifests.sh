#!/bin/sh
# Writes the winget manifests for one PolicyVice release.
# Usage: winget/manifests.sh <version> <PolicyVice.msi> <release notes file> <output folder>
set -e

version="$1"
msi="$2"
notes="$3"
out="$4"
if [ -z "$version" ] || [ ! -f "$msi" ] || [ -z "$out" ]; then
  echo "Usage: $0 <version> <PolicyVice.msi> <release notes file> <output folder>" >&2
  exit 2
fi

id=DanielBaldissera.PolicyVice
repo=Baldissera88/PolicyVice
schema=1.12.0
url="https://github.com/$repo/releases/download/v$version/PolicyVice.msi"
code=$(msiinfo export "$msi" Property | awk -F'\t' '$1=="ProductCode"{print $2}' | tr -d '\r')
upgrade=$(msiinfo export "$msi" Property | awk -F'\t' '$1=="UpgradeCode"{print $2}' | tr -d '\r')
sha=$(sha256sum "$msi" | cut -d' ' -f1 | tr 'a-f' 'A-F')
date=$(date -u +%Y-%m-%d)
dir="$out/manifests/d/DanielBaldissera/PolicyVice/$version"
mkdir -p "$dir"

cat > "$dir/$id.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.$schema.schema.json

PackageIdentifier: $id
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $schema
EOF

cat > "$dir/$id.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.$schema.schema.json

PackageIdentifier: $id
PackageVersion: $version
MinimumOSVersion: 10.0.14393.0
InstallerType: msi
Scope: machine
InstallModes:
- interactive
- silent
- silentWithProgress
UpgradeBehavior: install
ProductCode: '$code'
ReleaseDate: $date
AppsAndFeaturesEntries:
- DisplayName: PolicyVice
  Publisher: Daniel L. Baldissera
  ProductCode: '$code'
  UpgradeCode: '$upgrade'
Installers:
- Architecture: x64
  InstallerUrl: $url
  InstallerSha256: $sha
ManifestType: installer
ManifestVersion: $schema
EOF

{
  cat <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.$schema.schema.json

PackageIdentifier: $id
PackageVersion: $version
PackageLocale: en-US
Publisher: Daniel L. Baldissera
PublisherUrl: https://github.com/Baldissera88
PublisherSupportUrl: https://github.com/$repo/issues
Author: Daniel L. Baldissera
PackageName: PolicyVice
PackageUrl: https://github.com/$repo
License: MIT
LicenseUrl: https://github.com/$repo/blob/main/LICENSE
Copyright: Copyright (c) 2026 Daniel L. Baldissera
ShortDescription: Policy inspector for Intune, MDM and Group Policy on Windows devices.
Description: |-
  PolicyVice shows what policy is set on a Windows device, who set it, and why it failed or disappeared.
  It reads Intune/MDM policy, ingested ADMX, Group Policy, the policy registry and Intune apps, platform scripts and remediations, finds conflicts between MDM and Group Policy, orphaned and tattooed values and MDM errors, and records every policy change while it watches.
  Names and value meanings for about 3,100 Policy CSP settings are built in. It is read-only, and a companion to LogVice.
Moniker: policyvice
Tags:
- admx
- configmgr
- endpoint-management
- gpo
- group-policy
- intune
- mdm
- policy
- troubleshooting
- windows
EOF
  if [ -n "$notes" ] && [ -s "$notes" ] && grep -q '[^[:space:]]' "$notes"; then
    echo "ReleaseNotes: |-"
    tr -d '\r' < "$notes" | awk 'NF{found=1} found' | sed -e 's/[[:space:]]*$//' -e 's/^/  /' -e 's/^  $//'
  fi
  cat <<EOF
ReleaseNotesUrl: https://github.com/$repo/releases/tag/v$version
Documentations:
- DocumentLabel: Changelog
  DocumentUrl: https://github.com/$repo/blob/main/CHANGELOG.md
ManifestType: defaultLocale
ManifestVersion: $schema
EOF
} > "$dir/$id.locale.en-US.yaml"

echo "Wrote $dir"
