#!/bin/bash
# port.sh — Automated build pipeline for cygport packages
#
# Usage:
#   ./port.sh list                   # list available packages
#   ./port.sh <pkg>                  # full pipeline: download+apply+build+install
#   ./port.sh <pkg> --download       # download tarball only
#   ./port.sh <pkg> --extract        # download + extract
#   ./port.sh <pkg> --apply          # download + extract + apply patches
#   ./port.sh <pkg> --build          # build (source must already be patched)
#   ./port.sh <pkg> --install        # install binaries to INSTALL_DIR
#   ./port.sh <pkg> --clean          # remove build work directory

set -euo pipefail

CYGPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${CYGPORT_WORK:-/tmp/cygport-work}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[port] $*"; }

# ── usage ────────────────────────────────────────────────────────────
usage() {
    sed -n '2,12p' "$0" | sed 's/^# //'
    exit 1
}

# ── list packages ────────────────────────────────────────────────────
cmd_list() {
    printf "%-12s %-14s %s\n" PACKAGE VERSION URL
    printf "%-12s %-14s %s\n" "-------" "---------" "---"
    for conf in "$CYGPORT_DIR"/patches/*/pkg.conf; do
        [ -f "$conf" ] || continue
        pkg=$(basename "$(dirname "$conf")")
        (
            source "$conf"
            printf "%-12s %-14s %s\n" \
                "$pkg" \
                "${PKG_VERSION:-?}" \
                "${PKG_URL:-—}"
        )
    done
}

# ── load pkg.conf ────────────────────────────────────────────────────
load_pkg() {
    local pkg="$1"
    local conf="$CYGPORT_DIR/patches/$pkg/pkg.conf"
    [ -f "$conf" ] || die "No pkg.conf for '$pkg' (looked in $conf)"
    source "$conf"
    : "${PKG_NAME:=$pkg}"
    : "${BUILD_TYPE:=make}"
    : "${INSTALL_DIR:=/usr/local/bin}"
    : "${CMAKE_ARGS:=()}"
    : "${MAKE_ARGS:=()}"
    : "${INSTALL_BINS:=()}"
    WORK_SRC="$WORK_DIR/$PKG_SRCDIR"
}

# ── download ─────────────────────────────────────────────────────────
cmd_download() {
    local pkg="$1"; load_pkg "$pkg"
    mkdir -p "$WORK_DIR"
    local tarball="$WORK_DIR/$(basename "$PKG_URL")"
    if [ -f "$tarball" ]; then
        info "Already downloaded: $tarball"
        return
    fi
    info "Downloading $PKG_URL ..."
    curl -L --progress-bar -o "$tarball.tmp" "$PKG_URL"
    mv "$tarball.tmp" "$tarball"
    info "Saved: $tarball"
}

# ── extract ──────────────────────────────────────────────────────────
cmd_extract() {
    local pkg="$1"; load_pkg "$pkg"
    cmd_download "$pkg"
    local tarball="$WORK_DIR/$(basename "$PKG_URL")"
    if [ -d "$WORK_SRC" ]; then
        info "Already extracted: $WORK_SRC"
        return
    fi
    info "Extracting to $WORK_DIR ..."
    if [ -n "${PKG_EXTRACT_CMD:-}" ]; then
        (cd "$WORK_DIR" && eval "$PKG_EXTRACT_CMD" "$tarball")
    else
        tar -C "$WORK_DIR" -xf "$tarball"
    fi
    [ -d "$WORK_SRC" ] || die "Expected source dir not found after extract: $WORK_SRC"
    info "Source ready: $WORK_SRC"
}

# ── apply patches ────────────────────────────────────────────────────
cmd_apply() {
    local pkg="$1"; load_pkg "$pkg"
    cmd_extract "$pkg"
    local apply_sh="$CYGPORT_DIR/patches/$pkg/apply.sh"
    [ -f "$apply_sh" ] || die "No apply.sh for $pkg"

    # Skip if already patched (sentinel file)
    if [ -f "$WORK_SRC/.cygport-patched" ]; then
        info "Patches already applied (delete $WORK_SRC/.cygport-patched to reapply)"
        return
    fi

    info "Applying patches in $WORK_SRC ..."
    (cd "$WORK_SRC" && bash "$apply_sh")
    touch "$WORK_SRC/.cygport-patched"
    info "Patches applied."
}

# ── build ────────────────────────────────────────────────────────────
cmd_build() {
    local pkg="$1"; load_pkg "$pkg"
    [ -d "$WORK_SRC" ] || die "Source not found: $WORK_SRC (run: $0 $pkg --apply)"

    info "Building $pkg (type=$BUILD_TYPE) ..."

    case "$BUILD_TYPE" in
        cmake)
            local bdir="$WORK_SRC/build"
            mkdir -p "$bdir"
            (cd "$bdir"
             cmake .. "${CMAKE_ARGS[@]}"
             make -j"$JOBS" ${BUILD_TARGETS:-})
            ;;

        cmake_ninja)
            local bdir="$WORK_SRC/build"
            mkdir -p "$bdir"
            (cd "$bdir"
             cmake .. -G Ninja "${CMAKE_ARGS[@]}"
             ninja -j"$JOBS" ${BUILD_TARGETS:-})
            ;;

        make)
            (cd "$WORK_SRC"
             make -j"$JOBS" "${MAKE_ARGS[@]}" ${BUILD_TARGETS:-})
            ;;

        configure_make)
            (cd "$WORK_SRC"
             [ -x configure ] || die "No configure script in $WORK_SRC"
             ./configure "${CONFIGURE_ARGS[@]:-}"
             make -j"$JOBS" "${MAKE_ARGS[@]:-}" ${BUILD_TARGETS:-})
            ;;

        special)
            # pkg.conf defines pkg_build() function
            declare -f pkg_build >/dev/null || die "BUILD_TYPE=special but pkg_build() not defined"
            (cd "$WORK_SRC" && pkg_build)
            ;;
    esac

    info "Build done."
}

# ── install ──────────────────────────────────────────────────────────
cmd_install() {
    local pkg="$1"; load_pkg "$pkg"
    [ -d "$WORK_SRC" ] || die "Source not found: $WORK_SRC"

    # If pkg.conf defines pkg_install(), delegate to it
    if declare -f pkg_install >/dev/null 2>&1; then
        info "Installing $pkg (custom pkg_install) ..."
        (cd "$WORK_SRC" && pkg_install)
        info "Install done."
        return
    fi

    mkdir -p "$INSTALL_DIR"
    info "Installing to $INSTALL_DIR ..."

    for bin in "${INSTALL_BINS[@]}"; do
        local found
        # Search in build/ first, then source root
        found=$(find "$WORK_SRC" \( -name "$bin" -o -name "${bin}.exe" \) -type f \
                     ! -path '*/.git/*' 2>/dev/null | head -1)
        [ -n "$found" ] || die "Binary not found: $bin (searched in $WORK_SRC)"
        install -m 755 "$found" "$INSTALL_DIR/$(basename "$found")"
        info "  installed $(basename "$found") -> $INSTALL_DIR/"
    done
}

# ── clean ────────────────────────────────────────────────────────────
cmd_clean() {
    local pkg="$1"; load_pkg "$pkg"
    if [ -d "$WORK_SRC" ]; then
        info "Removing $WORK_SRC ..."
        rm -rf "$WORK_SRC"
    else
        info "Nothing to clean."
    fi
}

# ── main ─────────────────────────────────────────────────────────────
[ $# -ge 1 ] || usage

CMD="$1"; shift

case "$CMD" in
    list)
        cmd_list
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        pkg="$CMD"
        step="${1:-}"

        case "$step" in
            "")              cmd_download "$pkg"
                             cmd_apply "$pkg"
                             cmd_build "$pkg"
                             cmd_install "$pkg" ;;
            --download)      cmd_download "$pkg" ;;
            --extract)       cmd_extract "$pkg" ;;
            --apply)         cmd_apply "$pkg" ;;
            --build)         cmd_build "$pkg" ;;
            --install)       cmd_install "$pkg" ;;
            --clean)         cmd_clean "$pkg" ;;
            *)               usage ;;
        esac
        ;;
esac
