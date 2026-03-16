#!/bin/bash
# apply.sh — Apply tcpdump Cygwin/Npcap port patches
#
# Usage:
#   cd /path/to/tcpdump-4.99.6
#   bash /d/cygport/patches/tcpdump/apply.sh
#
# Prerequisites (install once):
#   - Npcap SDK headers in /opt/cygwin-port/include/pcap/
#   - libwpcap.a in /opt/cygwin-port/lib/
#   - pcap/pcap.h patched for __CYGWIN__ (see below)
#
# Build after applying:
#   mkdir -p build && cd build
#   cmake .. \
#     -DCMAKE_C_FLAGS='-I/opt/cygwin-port/include' \
#     -DCMAKE_EXE_LINKER_FLAGS='-L/opt/cygwin-port/lib' \
#     -DPCAP_ROOT=/opt/cygwin-port
#   make -j4
#
# NOTE: Also requires patching /opt/cygwin-port/include/pcap/pcap.h
# to override pcap_pkthdr for Cygwin LP64 ABI compatibility with Npcap.
# See tcpdump-cygwin-porting.md for details.

set -e
PATCH_DIR="$(dirname "$0")"
for patch in "$PATCH_DIR"/0*.patch; do
    echo "[+] Applying $patch"
    patch -p1 < "$patch"
done
echo "[+] All patches applied."
echo "[+] Build with: mkdir build && cd build && cmake .. -DCMAKE_C_FLAGS='-I/opt/cygwin-port/include' -DCMAKE_EXE_LINKER_FLAGS='-L/opt/cygwin-port/lib' -DPCAP_ROOT=/opt/cygwin-port && make -j4"
