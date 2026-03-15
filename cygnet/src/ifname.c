/*
 * ifname.c — Interface name mapping: dnet short name ↔ Npcap NPF path
 *
 * Problem being solved (from nmap source):
 *   my_pcap_open_live("eth0") → pcap_create("eth0") → Npcap fails (Error 123)
 *   because Npcap expects "\Device\NPF_{3B4...}" not "eth0".
 *
 * This module builds a bidirectional map by:
 *   1. Calling GetAdaptersAddresses() to enumerate all adapters with their GUIDs
 *   2. Calling pcap_findalldevs() (via lazy-loaded Npcap) to enumerate NPF devices
 *   3. Matching them by adapter index (IfIndex)
 *   4. Generating dnet-style names (eth0, eth1, lo0) by type + order
 *
 * Cache is built once on first call, then reused.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cygnet_internal.h"

/* ── Cache entry ─────────────────────────────────────────────────────────── */

#define IFNAME_MAX  64
#define NPF_MAX    256
#define CACHE_CAP   64

typedef struct {
    char  ifname[IFNAME_MAX];   /* "eth0", "lo0", ... */
    char  npf[NPF_MAX];         /* "\Device\NPF_{GUID}" */
    DWORD ifindex;
    int   type;                 /* IF_TYPE_ETHERNET_CSMACD, IF_TYPE_SOFTWARE_LOOPBACK, ... */
} IfEntry;

static IfEntry  cache[CACHE_CAP];
static int      cache_sz = 0;
static CRITICAL_SECTION cache_lock;
static INIT_ONCE init_once = INIT_ONCE_STATIC_INIT;

/* ── Forward declarations ────────────────────────────────────────────────── */
static void build_cache(void);
static BOOL CALLBACK build_cache_once(PINIT_ONCE, PVOID, PVOID*);

/* ── Public API ──────────────────────────────────────────────────────────── */

int cygnet_ifname_to_npf(const char *ifname, char *out, int outlen)
{
    InitOnceExecuteOnce(&init_once, build_cache_once, NULL, NULL);

    EnterCriticalSection(&cache_lock);
    for (int i = 0; i < cache_sz; i++) {
        if (strcmp(cache[i].ifname, ifname) == 0) {
            strncpy(out, cache[i].npf, outlen - 1);
            out[outlen - 1] = '\0';
            LeaveCriticalSection(&cache_lock);
            return 1;
        }
    }
    LeaveCriticalSection(&cache_lock);
    return 0;
}

int cygnet_npf_to_ifname(const char *npf, char *out, int outlen)
{
    InitOnceExecuteOnce(&init_once, build_cache_once, NULL, NULL);

    EnterCriticalSection(&cache_lock);
    for (int i = 0; i < cache_sz; i++) {
        if (strcasecmp(cache[i].npf, npf) == 0) {
            strncpy(out, cache[i].ifname, outlen - 1);
            out[outlen - 1] = '\0';
            LeaveCriticalSection(&cache_lock);
            return 1;
        }
    }
    LeaveCriticalSection(&cache_lock);
    return 0;
}

/* ── Cache builder ───────────────────────────────────────────────────────── */

static BOOL CALLBACK build_cache_once(PINIT_ONCE o, PVOID p, PVOID *ctx)
{
    (void)o; (void)p; (void)ctx;
    InitializeCriticalSection(&cache_lock);
    build_cache();
    return TRUE;
}

/*
 * Step 1: GetAdaptersAddresses → ifindex → GUID → NPF path
 * Step 2: pcap_findalldevs    → NPF path → description
 * Step 3: assign dnet-style names by (type, order)
 */
static void build_cache(void)
{
    /* ── Step 1: Enumerate Windows adapters ────────────────────────────── */
    ULONG buflen = 128 * 1024;
    IP_ADAPTER_ADDRESSES *addrs = malloc(buflen);
    if (!addrs) return;

    ULONG rc = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, addrs, &buflen);

    if (rc == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = malloc(buflen);
        if (!addrs) return;
        rc = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, addrs, &buflen);
    }

    if (rc != NO_ERROR) { free(addrs); return; }

    /* ── Step 2: Enumerate Npcap devices ───────────────────────────────── */
    pcap_if_t *devs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    /* Use lazy-loaded Npcap; if unavailable, NPF map will be empty */
    int has_pcap = (cygnet_npcap_pcap_findalldevs(&devs, errbuf) == 0);

    /* ── Step 3: Match adapter → NPF device by GUID ────────────────────── */
    /*
     * Npcap NPF device names look like:
     *   \Device\NPF_{3B4ABCD1-1234-...}
     * Windows adapter AdapterName is:
     *   {3B4ABCD1-1234-...}   (GUID without \Device\NPF_ prefix)
     */
    int eth_idx = 0, lo_idx = 0, wlan_idx = 0, other_idx = 0;

    for (IP_ADAPTER_ADDRESSES *a = addrs; a && cache_sz < CACHE_CAP; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp &&
            a->OperStatus != IfOperStatusDormant) continue;

        IfEntry *e = &cache[cache_sz];
        memset(e, 0, sizeof(*e));
        e->ifindex = a->IfIndex;
        e->type    = a->IfType;

        /* Assign dnet-style name by type */
        switch (a->IfType) {
        case IF_TYPE_SOFTWARE_LOOPBACK:
            snprintf(e->ifname, sizeof(e->ifname), "lo%d", lo_idx++);
            break;
        case IF_TYPE_IEEE80211:
            snprintf(e->ifname, sizeof(e->ifname), "wlan%d", wlan_idx++);
            break;
        case IF_TYPE_ETHERNET_CSMACD:
        case IF_TYPE_GIGABITETHERNET:
        case IF_TYPE_FASTETHER:
        case IF_TYPE_FASTETHER_FX:
        default:
            if (a->IfType == IF_TYPE_ETHERNET_CSMACD ||
                a->IfType == IF_TYPE_GIGABITETHERNET ||
                a->IfType == IF_TYPE_FASTETHER ||
                a->IfType == IF_TYPE_FASTETHER_FX)
                snprintf(e->ifname, sizeof(e->ifname), "eth%d", eth_idx++);
            else
                snprintf(e->ifname, sizeof(e->ifname), "if%d", other_idx++);
            break;
        }

        /* Build expected NPF path from adapter GUID */
        char expected_npf[NPF_MAX];
        snprintf(expected_npf, sizeof(expected_npf),
                 "\\Device\\NPF_%s", a->AdapterName);

        /* Try to find matching Npcap device */
        if (has_pcap) {
            for (pcap_if_t *d = devs; d; d = d->next) {
                if (strcasecmp(d->name, expected_npf) == 0) {
                    strncpy(e->npf, d->name, NPF_MAX - 1);
                    break;
                }
            }
        }

        /* If no Npcap match, still store the expected NPF path */
        if (e->npf[0] == '\0') {
            snprintf(e->npf, NPF_MAX, "%s", expected_npf);
        }

        cache_sz++;
    }

    if (has_pcap && devs)
        cygnet_npcap_pcap_freealldevs(devs);
    free(addrs);
}

/* ── Debug dump (for development) ───────────────────────────────────────── */
void cygnet_ifname_dump(void)
{
    InitOnceExecuteOnce(&init_once, build_cache_once, NULL, NULL);

    EnterCriticalSection(&cache_lock);
    fprintf(stderr, "[cygnet] interface map (%d entries):\n", cache_sz);
    for (int i = 0; i < cache_sz; i++) {
        fprintf(stderr, "  %-8s idx=%-4lu  %s\n",
                cache[i].ifname, (unsigned long)cache[i].ifindex,
                cache[i].npf);
    }
    LeaveCriticalSection(&cache_lock);
}
