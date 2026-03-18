#!/bin/bash
# apply.sh — Apply pcaprub Cygwin port patches
#
# Usage:
#   cd /path/to/pcaprub-0.13.3
#   bash /d/cygport/patches/pcaprub/apply.sh
#
# Prerequisites (install once):
#   - Npcap SDK headers in /opt/cygwin-port/include/
#   - libwpcap.a in /opt/cygwin-port/lib/
#   - ruby ruby-devel: apt install ruby ruby-devel
#
# Build after applying:
#   cd ext/pcaprub_c
#   ruby extconf.rb --with-pcap-dir=/opt/cygwin-port
#   make

set -e
PATCH_DIR="$(dirname "$0")"
for patch in "$PATCH_DIR"/0*.patch; do
    echo "[+] Applying $patch"
    patch -p1 < "$patch"
done
echo "[+] All patches applied."
echo "[+] Build with:"
echo "    cd ext/pcaprub_c"
echo "    ruby extconf.rb --with-pcap-dir=/opt/cygwin-port"
echo "    make"
