#!/bin/sh
# Builds PolicyVice.exe with Mono. Every src/*.cs file is compiled and every file in res/ is embedded under its file name.
set -e
cd "$(dirname "$0")"
API=/usr/lib/mono/4.5-api
SRC=$(ls src/*.cs | sort)
RES=""
for f in res/*; do [ -f "$f" ] && RES="$RES -resource:$f,$(basename "$f")"; done
mcs -langversion:5 -target:winexe -platform:anycpu -optimize+ -warn:4 -warnaserror+ -noconfig -nostdlib \
  -r:$API/mscorlib.dll -r:$API/System.dll -r:$API/System.Core.dll -r:$API/System.Xml.dll -r:$API/System.Runtime.Serialization.dll \
  -r:$API/System.Management.dll -r:$API/System.Drawing.dll -r:$API/System.Windows.Forms.dll \
  -win32icon:PolicyVice.ico -resource:PolicyVice.ico,PolicyVice.ico $RES -out:PolicyVice.exe $SRC
echo EXE_OK
