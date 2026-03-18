#!/bin/bash
# apply.sh — Apply hping3 Cygwin port patches
#
# Usage:
#   cd /path/to/hping-master    (or wherever the hping3 source is)
#   bash /d/cygport/patches/hping3/apply.sh
#
# Prerequisites (install once):
#   - Npcap SDK headers in /opt/cygwin-port/include/
#   - libwpcap.a in /opt/cygwin-port/lib/
#   - tcl-devel: apt install tcl-devel
#
# Build after applying:
#   ./configure
#   make COMPILE_TIME='-I/opt/cygwin-port/include -fcommon' \
#        PCAP='-L/opt/cygwin-port/lib -lwpcap' \
#        TCL='-ltcl8.6'

set -e
PATCH_DIR="$(dirname "$0")"
for patch in "$PATCH_DIR"/0*.patch; do
    echo "[+] Applying $patch"
    patch -p1 < "$patch"
done
echo "[+] All patches applied."
echo "[+] Build with:"
echo "    ./configure"
echo "    make COMPILE_TIME='-I/opt/cygwin-port/include -fcommon' PCAP='-L/opt/cygwin-port/lib -lwpcap' TCL='-ltcl8.6'"
