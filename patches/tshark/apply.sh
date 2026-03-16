#!/bin/bash
# apply.sh — Apply tshark (Wireshark 4.4.9) Cygwin/Npcap port patches
#
# Usage:
#   cd /path/to/wireshark-4.4.9
#   bash /d/cygport/patches/tshark/apply.sh
#
# Prerequisites (install once):
#   - Npcap SDK headers in /opt/cygwin-port/include/
#   - libwpcap.a in /opt/cygwin-port/lib/
#   - pcap/pcap.h patched for __CYGWIN__ (see tcpdump porting doc)
#   - speexdsp-devel installed: apt install speexdsp-devel
#
# Build after applying:
#   mkdir -p build && cd build
#   cmake .. -G Ninja \
#     -DBUILD_wireshark=OFF \
#     -DBUILD_logray=OFF \
#     -DENABLE_PCAP=ON \
#     -DPCAP_ROOT=/opt/cygwin-port \
#     -DCMAKE_C_FLAGS='-I/opt/cygwin-port/include' \
#     -DCMAKE_EXE_LINKER_FLAGS='-L/opt/cygwin-port/lib' \
#     -DPython3_EXECUTABLE=/usr/bin/python3
#   ninja tshark dumpcap
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
echo "[+] Build with:"
echo "    mkdir build && cd build"
echo "    cmake .. -G Ninja -DBUILD_wireshark=OFF -DBUILD_logray=OFF -DENABLE_PCAP=ON -DPCAP_ROOT=/opt/cygwin-port -DCMAKE_C_FLAGS='-I/opt/cygwin-port/include' -DCMAKE_EXE_LINKER_FLAGS='-L/opt/cygwin-port/lib' -DPython3_EXECUTABLE=/usr/bin/python3"
echo "    ninja tshark dumpcap"
