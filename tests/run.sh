#!/bin/sh
# Builds the core logic with the tests and runs them under Mono.
set -e
cd "$(dirname "$0")/.."
API=/usr/lib/mono/4.5-api
mcs -langversion:5 -target:exe -warn:4 -warnaserror+ -noconfig -nostdlib \
  -r:$API/mscorlib.dll -r:$API/System.dll -r:$API/System.Core.dll -r:$API/System.Xml.dll -r:$API/System.Runtime.Serialization.dll -r:$API/System.Management.dll \
  -out:tests/PolicyViceTests.exe src/Model.cs src/Sources.cs src/Admx.cs src/Collect.cs src/Diff.cs src/Report.cs tests/PolicyViceTests.cs
mono tests/PolicyViceTests.exe "$@"
