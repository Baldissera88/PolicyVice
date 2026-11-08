#!/bin/sh
set -e
cd "$(dirname "$0")"
./build.sh
wixl -a x64 -o PolicyVice.msi PolicyVice.wxs
./patch_msi.sh "$PWD/PolicyVice.msi"
echo PACKAGE_OK
