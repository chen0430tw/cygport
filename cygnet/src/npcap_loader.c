/*
 * npcap_loader.c — Lazy loader for Npcap's wpcap.dll
 *
 * Problem being solved:
 *   Tools (nmap, tcpdump) are compiled against wpcap.dll at link time,
 *   causing hard dependency and version conflicts.
 *
 *   CygNet instead loads wpcap.dll at runtime on first use,
 *   probing standard Npcap installation paths.
 *   If not found, WinDivert-based fallback is used instead.
 *
 * All pcap_* function pointers are resolved here.
 * Other modules call cygnet_npcap_*() wrappers defined in this file.
 */

#include <winsock2.h>
#include <windows.h>

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "cygnet_internal.h"

/*
 * Npcap is a Windows DLL — its pcap_pkthdr uses Windows struct timeval:
 *   tv_sec  = 32-bit long (4 bytes)
 *   tv_usec = 32-bit long (4 bytes)
 *   total   = 8 bytes
 *
 * Cygwin defines struct timeval with 64-bit time_t / suseconds_t:
 *   tv_sec  = 64-bit (8 bytes)
 *   tv_usec = 64-bit (8 bytes)
 *   total   = 16 bytes
 *
 * pcap_pkthdr returned by Npcap must be converted before handing to Cygwin.
 */
typedef struct {
    uint32_t tv_sec;
    uint32_t tv_usec;
    uint32_t caplen;
    uint32_t len;
} NpcapPkthdr;

static void npcap_hdr_to_cygwin(const NpcapPkthdr *src, struct pcap_pkthdr *dst)
{
    dst->ts.tv_sec  = (time_t)src->tv_sec;
    dst->ts.tv_usec = (suseconds_t)src->tv_usec;
    dst->caplen     = src->caplen;
    dst->len        = src->len;
}

/* ── Npcap probe paths (in priority order) ───────────────────────────────── */
static const char *NPCAP_PATHS[] = {
    "C:\\Windows\\System32\\Npcap\\wpcap.dll",   /* standard Npcap install */
    "C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll",   /* 32-bit on 64-bit */
    "wpcap.dll",                                   /* on PATH */
    NULL
};

/* ── Function pointer table ──────────────────────────────────────────────── */
typedef struct {
    HMODULE hMod;

    /* capture lifecycle */
    pcap_t* (*open_live)    (const char*, int, int, int, char*);
    pcap_t* (*create)       (const char*, char*);
    int     (*set_snaplen)  (pcap_t*, int);
    int     (*set_promisc)  (pcap_t*, int);
    int     (*set_timeout)  (pcap_t*, int);
    int     (*set_imm_mode) (pcap_t*, int);
    int     (*activate)     (pcap_t*);
    void    (*close)        (pcap_t*);

    /* filter */
    int     (*compile)      (pcap_t*, struct bpf_program*, const char*, int, bpf_u_int32);
    int     (*setfilter)    (pcap_t*, struct bpf_program*);
    void    (*freecode)     (struct bpf_program*);

    /* capture */
    int     (*next_ex)      (pcap_t*, struct pcap_pkthdr**, const u_char**);
    int     (*dispatch)     (pcap_t*, int, pcap_handler, u_char*);
    void    (*breakloop)    (pcap_t*);

    /* inject */
    int     (*inject)       (pcap_t*, const void*, size_t);
    int     (*sendpacket)   (pcap_t*, const u_char*, int);

    /* enumeration */
    int     (*findalldevs)  (pcap_if_t**, char*);
    void    (*freealldevs)  (pcap_if_t*);

    /* info */
    int     (*datalink)     (pcap_t*);
    char*   (*geterr)       (pcap_t*);
    const char* (*lib_version)(void);
} NpcapFuncs;

static NpcapFuncs npcap;
static int        npcap_loaded  = 0;   /* 1=found, -1=not found */
static INIT_ONCE  load_once     = INIT_ONCE_STATIC_INIT;

/* ── Macro helpers ───────────────────────────────────────────────────────── */
#define LOAD_SYM(field, name) \
    npcap.field = (void*)GetProcAddress(npcap.hMod, name); \
    if (!npcap.field) { \
        fprintf(stderr, "[cygnet] WARNING: wpcap.dll missing symbol: %s\n", name); \
    }

/* ── Loader ──────────────────────────────────────────────────────────────── */
static BOOL CALLBACK do_load(PINIT_ONCE o, PVOID p, PVOID *ctx)
{
    (void)o; (void)p; (void)ctx;

    for (int i = 0; NPCAP_PATHS[i]; i++) {
        npcap.hMod = LoadLibraryA(NPCAP_PATHS[i]);
        if (npcap.hMod) {
            fprintf(stderr, "[cygnet] Loaded Npcap from: %s\n", NPCAP_PATHS[i]);
            break;
        }
    }

    if (!npcap.hMod) {
        fprintf(stderr, "[cygnet] Npcap not found, using WinDivert fallback\n");
        npcap_loaded = -1;
        return TRUE;
    }

    LOAD_SYM(open_live,   "pcap_open_live");
    LOAD_SYM(create,      "pcap_create");
    LOAD_SYM(set_snaplen, "pcap_set_snaplen");
    LOAD_SYM(set_promisc, "pcap_set_promisc");
    LOAD_SYM(set_timeout, "pcap_set_timeout");
    LOAD_SYM(set_imm_mode,"pcap_set_immediate_mode");
    LOAD_SYM(activate,    "pcap_activate");
    LOAD_SYM(close,       "pcap_close");

    LOAD_SYM(compile,     "pcap_compile");
    LOAD_SYM(setfilter,   "pcap_setfilter");
    LOAD_SYM(freecode,    "pcap_freecode");

    LOAD_SYM(next_ex,     "pcap_next_ex");
    LOAD_SYM(dispatch,    "pcap_dispatch");
    LOAD_SYM(breakloop,   "pcap_breakloop");

    LOAD_SYM(inject,      "pcap_inject");
    LOAD_SYM(sendpacket,  "pcap_sendpacket");

    LOAD_SYM(findalldevs, "pcap_findalldevs");
    LOAD_SYM(freealldevs, "pcap_freealldevs");

    LOAD_SYM(datalink,    "pcap_datalink");
    LOAD_SYM(geterr,      "pcap_geterr");
    LOAD_SYM(lib_version, "pcap_lib_version");

    npcap_loaded = 1;
    return TRUE;
}

static inline void ensure_loaded(void)
{
    InitOnceExecuteOnce(&load_once, do_load, NULL, NULL);
}

/* ── Public: status ──────────────────────────────────────────────────────── */
int cygnet_npcap_available(void)
{
    ensure_loaded();
    return npcap_loaded == 1;
}

/* ── Public: wrappers used by other cygnet modules ───────────────────────── */

int cygnet_npcap_pcap_findalldevs(pcap_if_t **alldevs, char *errbuf)
{
    ensure_loaded();
    if (npcap_loaded != 1 || !npcap.findalldevs) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "Npcap not available");
        return -1;
    }
    return npcap.findalldevs(alldevs, errbuf);
}

void cygnet_npcap_pcap_freealldevs(pcap_if_t *alldevs)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.freealldevs)
        npcap.freealldevs(alldevs);
}

/* ── Public: full pcap_* shim (exported as pcap_* symbols) ─────────────── */
/*
 * These are the functions that tools (nmap, tcpdump) actually call.
 * We intercept here to:
 *   1. Translate interface names (eth0 → \Device\NPF_{GUID})
 *   2. Delegate to Npcap if available
 *   3. Fall back to WinDivert otherwise
 */

pcap_t *pcap_open_live(const char *device, int snaplen,
                        int promisc, int to_ms, char *errbuf)
{
    ensure_loaded();

    char npfdev[256];
    const char *dev = device;
    if (cygnet_ifname_to_npf(device, npfdev, sizeof(npfdev)))
        dev = npfdev;

    if (npcap_loaded == 1 && npcap.open_live)
        return npcap.open_live(dev, snaplen, promisc, to_ms, errbuf);

    return cygnet_windivert_open(dev, snaplen, promisc, to_ms, errbuf);
}

pcap_t *pcap_create(const char *device, char *errbuf)
{
    ensure_loaded();

    char npfdev[256];
    const char *dev = device;
    if (cygnet_ifname_to_npf(device, npfdev, sizeof(npfdev)))
        dev = npfdev;

    if (npcap_loaded == 1 && npcap.create)
        return npcap.create(dev, errbuf);

    return cygnet_windivert_open(dev, 65535, 1, 0, errbuf);
}

/* set_* and activate: transparent pass-through */
#define PASSTHRU_INT1(fn, field, T1) \
    int fn(pcap_t *p, T1 v) { \
        ensure_loaded(); \
        if (npcap_loaded == 1 && npcap.field) return npcap.field(p, v); \
        return cygnet_windivert_##field(p, v); \
    }

PASSTHRU_INT1(pcap_set_snaplen,        set_snaplen,  int)
PASSTHRU_INT1(pcap_set_promisc,        set_promisc,  int)
PASSTHRU_INT1(pcap_set_timeout,        set_timeout,  int)
PASSTHRU_INT1(pcap_set_immediate_mode, set_imm_mode, int)

int pcap_activate(pcap_t *p)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.activate) return npcap.activate(p);
    return cygnet_windivert_activate(p);
}

void pcap_close(pcap_t *p)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.close) { npcap.close(p); return; }
    cygnet_windivert_close(p);
}

int pcap_compile(pcap_t *p, struct bpf_program *fp,
                 const char *str, int opt, bpf_u_int32 mask)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.compile)
        return npcap.compile(p, fp, str, opt, mask);
    return cygnet_windivert_compile(p, fp, str, opt, mask);
}

int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.setfilter) return npcap.setfilter(p, fp);
    return cygnet_windivert_setfilter(p, fp);
}

void pcap_freecode(struct bpf_program *fp)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.freecode) npcap.freecode(fp);
}

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **hdr, const u_char **data)
{
    ensure_loaded();
    if (npcap_loaded != 1 || !npcap.next_ex)
        return cygnet_windivert_next_ex(p, hdr, data);

    /* Npcap returns a pointer to its internal NpcapPkthdr (32-bit timeval).
     * Convert to Cygwin pcap_pkthdr (64-bit timeval) before returning. */
    NpcapPkthdr *whdr = NULL;
    int ret = npcap.next_ex(p, (struct pcap_pkthdr **)&whdr, data);
    if (ret == 1 && whdr) {
        static struct pcap_pkthdr converted;
        npcap_hdr_to_cygwin(whdr, &converted);
        *hdr = &converted;
    }
    return ret;
}

/* Wrapper state for pcap_dispatch callback conversion */
typedef struct {
    pcap_handler real_cb;
    u_char      *real_user;
} DispatchWrap;

static void dispatch_cb_wrapper(u_char *arg,
                                 const struct pcap_pkthdr *raw_hdr,
                                 const u_char *data)
{
    /* raw_hdr points to Npcap's NpcapPkthdr — convert before calling Cygwin cb */
    DispatchWrap *w = (DispatchWrap *)arg;
    struct pcap_pkthdr converted;
    npcap_hdr_to_cygwin((const NpcapPkthdr *)raw_hdr, &converted);
    w->real_cb(w->real_user, &converted, data);
}

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler cb, u_char *user)
{
    ensure_loaded();
    if (npcap_loaded != 1 || !npcap.dispatch)
        return cygnet_windivert_dispatch(p, cnt, cb, user);

    DispatchWrap w = { cb, user };
    return npcap.dispatch(p, cnt, dispatch_cb_wrapper, (u_char *)&w);
}

void pcap_breakloop(pcap_t *p)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.breakloop) npcap.breakloop(p);
    else cygnet_windivert_breakloop(p);
}

int pcap_inject(pcap_t *p, const void *buf, size_t size)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.inject) return npcap.inject(p, buf, size);
    return cygnet_windivert_inject(p, buf, (int)size);
}

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.sendpacket) return npcap.sendpacket(p, buf, size);
    return cygnet_windivert_inject(p, buf, size);
}

int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf)
{
    ensure_loaded();
    int ret;
    if (npcap_loaded == 1 && npcap.findalldevs)
        ret = npcap.findalldevs(alldevs, errbuf);
    else
        ret = cygnet_windivert_findalldevs(alldevs, errbuf);

    /* Post-process: add dnet-style name aliases to each device.
     * NOTE: Do NOT free/replace d->description — those strings belong to
     * Npcap's allocator; freeing them with Cygwin's free() causes heap
     * corruption when npcap.freealldevs later tries to free them. */
    if (ret == 0 && alldevs) {
        for (pcap_if_t *d = *alldevs; d; d = d->next) {
            char ifname[64];
            cygnet_npf_to_ifname(d->name, ifname, sizeof(ifname));
        }
    }
    return ret;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.freealldevs) npcap.freealldevs(alldevs);
    else cygnet_windivert_freealldevs(alldevs);
}

int pcap_datalink(pcap_t *p)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.datalink) return npcap.datalink(p);
    return DLT_EN10MB;  /* WinDivert always delivers Ethernet frames */
}

char *pcap_geterr(pcap_t *p)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.geterr) return npcap.geterr(p);
    return cygnet_windivert_geterr(p);
}

const char *pcap_lib_version(void)
{
    ensure_loaded();
    if (npcap_loaded == 1 && npcap.lib_version) return npcap.lib_version();
    return "CygNet/" CYGNET_VERSION " (WinDivert fallback)";
}
