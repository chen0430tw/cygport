/*
 * cygnet.h — CygNet public API
 *
 * CygNet is a pcap/raw-socket shim for Cygwin.
 * It intercepts pcap_* calls, fixes interface naming, and lazily loads
 * Npcap (wpcap.dll) on demand. Falls back to WinDivert if Npcap is absent.
 *
 * Tools link against cygnet.dll instead of wpcap.dll.
 * No source changes needed.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ── Interface name mapping ──────────────────────────────────────────────── */

/*
 * cygnet_ifname_to_npf:
 *   Translate a dnet-style short name (e.g. "eth0", "lo0") to the Npcap
 *   NPF device path (e.g. "\Device\NPF_{GUID}").
 *
 *   Returns 1 on success (out filled), 0 if not found.
 *   Thread-safe; results are cached internally.
 */
int cygnet_ifname_to_npf(const char *ifname, char *out, int outlen);

/*
 * cygnet_npf_to_ifname:
 *   Reverse lookup: NPF path → short name.
 *   Returns 1 on success, 0 if not found.
 */
int cygnet_npf_to_ifname(const char *npf, char *out, int outlen);

/* ── Npcap lazy loader ───────────────────────────────────────────────────── */

/*
 * cygnet_npcap_available:
 *   Returns 1 if Npcap (wpcap.dll) was found and loaded, 0 otherwise.
 *   Triggers load on first call.
 */
int cygnet_npcap_available(void);

/* ── Debug ───────────────────────────────────────────────────────────────── */
/* Print full interface map to stderr (for diagnostics) */
void cygnet_ifname_dump(void);

/* ── Version ─────────────────────────────────────────────────────────────── */
#define CYGNET_VERSION "0.1.0"

#ifdef __cplusplus
}
#endif
