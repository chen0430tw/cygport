#!/bin/bash
# apply.sh — Apply masscan Cygwin/cygnet port patches
#
# Usage: cd /path/to/masscan && bash /d/cygport/patches/masscan/apply.sh
#
# Patches are relative to masscan source root (git diff format).
# Requires: cygnet.dll + libcygnet.dll.a at /d/cygport/cygnet/
#           WinDivert.dll + WinDivert.sys installed (e.g. via Npcap or standalone)

set -e

PATCH_DIR="$(dirname "$0")"

for patch in "$PATCH_DIR"/0*.patch; do
    echo "[+] Applying $patch"
    patch -p1 < "$patch"
done

echo "[+] All patches applied."
echo "[+] Build with: make -j4"
echo "[+] Run with:   sudo masscan.exe --source-ip <IP> -e <NPF_device> --router-mac <GW_MAC> --source-mac <SRC_MAC> -p<ports> <targets>"
