#!/bin/sh
set -e
cd "$(dirname "$0")"
API=/usr/lib/mono/4.5-api
SRC="src/AssemblyInfo.cs src/Model.cs src/Sources.cs src/Admx.cs src/Collect.cs src/Diff.cs src/Report.cs src/Demo.cs src/LogViceLink.cs src/Ui.Theme.cs src/Ui.Controls.cs src/Ui.MainForm.cs src/Program.cs"
mcs -langversion:5 -target:winexe -platform:anycpu -optimize+ -warn:4 -warnaserror+ -noconfig -nostdlib \
  -r:$API/mscorlib.dll -r:$API/System.dll -r:$API/System.Core.dll -r:$API/System.Xml.dll -r:$API/System.Runtime.Serialization.dll \
  -r:$API/System.Management.dll -r:$API/System.Drawing.dll -r:$API/System.Windows.Forms.dll \
  -win32icon:PolicyVice.ico -resource:PolicyVice.ico,PolicyVice.ico -out:PolicyVice.exe $SRC
echo EXE_OK
