#!/bin/bash
# Apply cygport patches to installed nmap/zenmap files.
# Run after: apt install nmap  OR  manual nmap build+install

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZENMAP_APP="/usr/local/lib/python3.9/site-packages/zenmapGUI/App.py"

if [ ! -f "$ZENMAP_APP" ]; then
    echo "zenmap not installed at $ZENMAP_APP — skipping"
    exit 0
fi

# Check if already patched
if grep -q '"cygwin"' "$ZENMAP_APP"; then
    echo "zenmap-cygwin-is-root: already applied"
    exit 0
fi

patch -p1 --directory=/ < "$SCRIPT_DIR/zenmap-cygwin-is-root.patch"
echo "zenmap-cygwin-is-root: applied"
