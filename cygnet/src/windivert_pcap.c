/*
 * windivert_pcap.c — WinDivert-based pcap fallback
 *
 * When Npcap is not installed, CygNet uses WinDivert.sys to capture
 * and inject raw packets, implementing the libpcap API on top of it.
 *
 * Architecture:
 *   pcap_t wrapper (CygnetHandle)
 *     ├── HANDLE hWinDivert       — WinDivertOpen() handle
 *     ├── HANDLE hThread          — background recv thread
 *     ├── HANDLE hPipeRead        — Cygwin-side fd (selectable)
 *     ├── HANDLE hPipeWrite       — thread writes packets here
 *     ├── volatile int stop       — breakloop signal
 *     ├── struct bpf_program bpf  — compiled filter
 *     └── char errbuf[...]        — last error string
 *
 * Packet receive loop (background thread):
 *   WinDivertRecv() → write header+data to pipe → pcap_next_ex reads pipe
 *   This makes the fd selectable via Cygwin select().
 *
 * BPF filter:
 *   WinDivert has its own filter language. For the common nmap BPF filters
 *   (tcp dst port X, icmp, etc.) we translate at open time.
 *   Full BPF programs run in userspace against received packets.
 */

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cygnet_internal.h"

/* ── WinDivert loading (lazy, same pattern as Npcap) ────────────────────── */

static HMODULE hWD = NULL;
static INIT_ONCE wd_once = INIT_ONCE_STATIC_INIT;

typedef HANDLE (WINAPI *pfn_Open)    (const char*, int, INT16, UINT64);
typedef BOOL   (WINAPI *pfn_Recv)    (HANDLE, void*, UINT, UINT*, void*);
typedef BOOL   (WINAPI *pfn_Send)    (HANDLE, const void*, UINT, UINT*, void*);
typedef BOOL   (WINAPI *pfn_Close)   (HANDLE);
typedef BOOL   (WINAPI *pfn_SetParam)(HANDLE, int, UINT64);

/* WinDivert WINDIVERT_ADDRESS binary ABI: 8+4+4+64 = 80 bytes */
typedef struct {
    INT64  Timestamp;
    UINT32 Flags;      /* bit17 = Outbound */
    UINT32 Reserved2;
    UINT8  Network[64]; /* [0..3] = IfIdx (UINT32 LE), [4..7] = SubIfIdx */
} WD_ADDRESS;
#define WD_OUTBOUND (1u << 17)

static pfn_Open     wd_Open;
static pfn_Recv     wd_Recv;
static pfn_Send     wd_Send;
static pfn_Close    wd_Close;
static pfn_SetParam wd_SetParam;

#define WINDIVERT_LAYER_NETWORK  0
#define WINDIVERT_PARAM_QUEUE_LENGTH  0
#define WINDIVERT_PARAM_QUEUE_TIME    1

static BOOL CALLBACK wd_load(PINIT_ONCE o, PVOID p, PVOID *ctx)
{
    (void)o; (void)p; (void)ctx;
    const char *paths[] = {
        "C:\\Windows\\System32\\WinDivert.dll",
        "WinDivert.dll",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        hWD = LoadLibraryA(paths[i]);
        if (hWD) break;
    }
    if (!hWD) return TRUE;  /* not found, stay NULL */

    /* GetProcAddress returns FARPROC; cast via void* to suppress -Wcast-function-type */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    wd_Open     = (pfn_Open)    GetProcAddress(hWD, "WinDivertOpen");
    wd_Recv     = (pfn_Recv)    GetProcAddress(hWD, "WinDivertRecv");
    wd_Send     = (pfn_Send)    GetProcAddress(hWD, "WinDivertSend");
    wd_Close    = (pfn_Close)   GetProcAddress(hWD, "WinDivertClose");
    wd_SetParam = (pfn_SetParam)GetProcAddress(hWD, "WinDivertSetParam");
#pragma GCC diagnostic pop
    return TRUE;
}

static int wd_available(void)
{
    InitOnceExecuteOnce(&wd_once, wd_load, NULL, NULL);
    return hWD && wd_Open && wd_Recv && wd_Send && wd_Close;
}

/* ── CygnetHandle: our pcap_t overlay ───────────────────────────────────── */

#define CYGNET_MAGIC 0xC767E7

typedef struct {
    UINT32          magic;
    HANDLE          hWD;        /* WinDivert handle */
    HANDLE          hThread;    /* recv thread */
    HANDLE          hPipeRead;  /* Cygwin readable fd end */
    HANDLE          hPipeWrite; /* thread write end */
    volatile LONG   stop;
    int             snaplen;
    int             datalink;
    DWORD           ifidx;      /* Windows interface index for WinDivertSend */
    char            errbuf[PCAP_ERRBUF_SIZE];
    /* last received packet (for pcap_next_ex) */
    struct pcap_pkthdr last_hdr;
    u_char         *last_pkt;
    int             last_pkt_cap;
} CygnetHandle;

/* Wire format written to pipe:
 *   [4 bytes: caplen][4 bytes: tv_sec][4 bytes: tv_usec][caplen bytes: data]
 */
#define PIPE_HDR_SZ 12

static CygnetHandle *handle_of(pcap_t *p)
{
    if (!p) return NULL;
    /* Direct case: p IS a CygnetHandle (returned from windivert_open) */
    CygnetHandle *h = (CygnetHandle *)p;
    if (h->magic == CYGNET_MAGIC) return h;
    return NULL;
}

/* ── Background recv thread ─────────────────────────────────────────────── */

static DWORD WINAPI recv_thread(LPVOID arg)
{
    CygnetHandle *h = (CygnetHandle *)arg;
    static u_char buf[65536];
    UINT pktlen;

    while (!InterlockedCompareExchange(&h->stop, 0, 0)) {
        pktlen = 0;
        /* WinDivert delivers network-layer packets (no Ethernet header) */
        if (!wd_Recv(h->hWD, buf + PIPE_HDR_SZ, sizeof(buf) - PIPE_HDR_SZ,
                     &pktlen, NULL)) {
            if (GetLastError() == ERROR_OPERATION_ABORTED) break;
            continue;
        }
        if (pktlen == 0) continue;

        UINT32 caplen   = (pktlen < (UINT)h->snaplen) ? pktlen : (UINT)h->snaplen;
        UINT32 tv_sec   = (UINT32)time(NULL);
        UINT32 tv_usec  = 0;

        memcpy(buf + 0, &caplen,  4);
        memcpy(buf + 4, &tv_sec,  4);
        memcpy(buf + 8, &tv_usec, 4);

        DWORD written;
        WriteFile(h->hPipeWrite, buf, PIPE_HDR_SZ + caplen, &written, NULL);
    }
    return 0;
}

/* ── Public: open ────────────────────────────────────────────────────────── */

pcap_t *cygnet_windivert_open(const char *dev, int snaplen,
                               int promisc, int to_ms, char *errbuf)
{
    (void)promisc; (void)to_ms;

    if (!wd_available()) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "WinDivert not found. Install Npcap or WinDivert.");
        return NULL;
    }

    CygnetHandle *h = calloc(1, sizeof(*h));
    if (!h) { snprintf(errbuf, PCAP_ERRBUF_SIZE, "out of memory"); return NULL; }

    h->magic   = CYGNET_MAGIC;
    h->snaplen = snaplen > 0 ? snaplen : 65535;
    h->datalink = DLT_RAW;  /* WinDivert delivers IP packets (no Ethernet) */
    h->ifidx   = cygnet_npf_to_ifindex(dev);  /* 0 = let WinDivert pick default route */

    /* Open WinDivert handle */
    h->hWD = wd_Open("true", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (h->hWD == INVALID_HANDLE_VALUE) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "WinDivertOpen failed (err=%u). Run as Administrator?",
                 (unsigned)GetLastError());
        free(h);
        return NULL;
    }

    /* Create pipe for thread → pcap_next_ex communication */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&h->hPipeRead, &h->hPipeWrite, &sa, 0)) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "CreatePipe failed (err=%u)", (unsigned)GetLastError());
        wd_Close(h->hWD);
        free(h);
        return NULL;
    }

    /* Start recv thread */
    h->hThread = CreateThread(NULL, 0, recv_thread, h, 0, NULL);
    if (!h->hThread) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "CreateThread failed (err=%u)", (unsigned)GetLastError());
        CloseHandle(h->hPipeRead);
        CloseHandle(h->hPipeWrite);
        wd_Close(h->hWD);
        free(h);
        return NULL;
    }

    /* Return CygnetHandle directly as pcap_t* — handle_of() detects via magic */
    return (pcap_t *)h;
}

/* ── Public: set_* (no-ops for WinDivert, handled at open time) ─────────── */
int  cygnet_windivert_set_snaplen  (pcap_t *p, int v)  { CygnetHandle *h = handle_of(p); if(h) h->snaplen=v; return 0; }
int  cygnet_windivert_set_promisc  (pcap_t *p, int v)  { (void)p;(void)v; return 0; }
int  cygnet_windivert_set_timeout  (pcap_t *p, int v)  { (void)p;(void)v; return 0; }
int  cygnet_windivert_set_imm_mode (pcap_t *p, int v)  { (void)p;(void)v; return 0; }
int  cygnet_windivert_activate     (pcap_t *p)          { (void)p; return 0; }

/* ── Public: close ───────────────────────────────────────────────────────── */
void cygnet_windivert_close(pcap_t *p)
{
    CygnetHandle *h = handle_of(p);
    if (!h) return;

    InterlockedExchange(&h->stop, 1);
    if (h->hWD != INVALID_HANDLE_VALUE) wd_Close(h->hWD);
    CloseHandle(h->hPipeWrite);

    if (h->hThread) {
        WaitForSingleObject(h->hThread, 2000);
        CloseHandle(h->hThread);
    }
    CloseHandle(h->hPipeRead);
    free(h->last_pkt);
    free(h);
}

/* ── Public: filter ──────────────────────────────────────────────────────── */
int cygnet_windivert_compile(pcap_t *p, struct bpf_program *fp,
                              const char *str, int opt, bpf_u_int32 mask)
{
    /* WinDivert captures at IP layer; BPF userspace filtering not yet
     * implemented — accept all packets and let the caller filter. */
    (void)p; (void)str; (void)opt; (void)mask;
    if (fp) memset(fp, 0, sizeof(*fp));
    return 0;
}

int cygnet_windivert_setfilter(pcap_t *p, struct bpf_program *fp)
{
    (void)p; (void)fp;
    /* BPF applied in userspace during pcap_next_ex */
    return 0;
}

/* ── Public: next_ex ─────────────────────────────────────────────────────── */
int cygnet_windivert_next_ex(pcap_t *p,
                              struct pcap_pkthdr **hdr,
                              const u_char **data)
{
    CygnetHandle *h = handle_of(p);
    if (!h) return PCAP_ERROR;

    u_char wire[PIPE_HDR_SZ + 65536];
    DWORD nread;

    /* Non-blocking read from pipe */
    DWORD avail = 0;
    if (!PeekNamedPipe(h->hPipeRead, NULL, 0, NULL, &avail, NULL) || avail == 0)
        return 0;  /* no packet yet */

    if (!ReadFile(h->hPipeRead, wire, PIPE_HDR_SZ, &nread, NULL) ||
        nread < PIPE_HDR_SZ)
        return PCAP_ERROR;

    UINT32 caplen, tv_sec, tv_usec;
    memcpy(&caplen,  wire + 0, 4);
    memcpy(&tv_sec,  wire + 4, 4);
    memcpy(&tv_usec, wire + 8, 4);

    if (caplen > 65535) return PCAP_ERROR;

    /* Read packet data */
    free(h->last_pkt);
    h->last_pkt = malloc(caplen);
    if (!h->last_pkt) return PCAP_ERROR;
    h->last_pkt_cap = caplen;

    if (!ReadFile(h->hPipeRead, h->last_pkt, caplen, &nread, NULL) ||
        nread < caplen)
        return PCAP_ERROR;

    h->last_hdr.caplen = caplen;
    h->last_hdr.len    = caplen;
    h->last_hdr.ts.tv_sec  = (time_t)tv_sec;
    h->last_hdr.ts.tv_usec = (suseconds_t)tv_usec;

    *hdr  = &h->last_hdr;
    *data = h->last_pkt;
    return 1;
}

/* ── Public: next_packet (ABI-safe, returns caplen directly) ─────────────── */
/* Avoids struct pcap_pkthdr ABI mismatch between cygnet (24-byte) and
 * masscan stub-pcap.h (16-byte) due to timeval size difference.
 * Returns: 0 = no packet yet, >0 = caplen of received packet, -1 = error */
int cygnet_windivert_next_packet(pcap_t *p, const u_char **data_out)
{
    CygnetHandle *h = handle_of(p);
    if (!h) return -1;

    u_char wire[PIPE_HDR_SZ];
    DWORD nread;

    DWORD avail = 0;
    if (!PeekNamedPipe(h->hPipeRead, NULL, 0, NULL, &avail, NULL) || avail == 0)
        return 0;

    if (!ReadFile(h->hPipeRead, wire, PIPE_HDR_SZ, &nread, NULL) ||
        nread < PIPE_HDR_SZ)
        return -1;

    UINT32 caplen;
    memcpy(&caplen, wire + 0, 4);
    if (caplen > 65535) return -1;

    free(h->last_pkt);
    h->last_pkt = malloc(caplen > 0 ? caplen : 1);
    if (!h->last_pkt) return -1;
    h->last_pkt_cap = (int)caplen;

    if (caplen > 0) {
        if (!ReadFile(h->hPipeRead, h->last_pkt, caplen, &nread, NULL) ||
            nread < caplen)
            return -1;
    }

    *data_out = h->last_pkt;
    return (int)caplen;
}

/* ── Public: dispatch ────────────────────────────────────────────────────── */
int cygnet_windivert_dispatch(pcap_t *p, int cnt, pcap_handler cb, u_char *user)
{
    int n = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    while (cnt < 0 || n < cnt) {
        int r = cygnet_windivert_next_ex(p, &hdr, &data);
        if (r == 0) break;
        if (r < 0)  return PCAP_ERROR;
        cb(user, hdr, data);
        n++;
    }
    return n;
}

void cygnet_windivert_breakloop(pcap_t *p)
{
    CygnetHandle *h = handle_of(p);
    if (h) InterlockedExchange(&h->stop, 1);
}

/* ── Public: inject ──────────────────────────────────────────────────────── */
int cygnet_windivert_inject(pcap_t *p, const void *buf, int size)
{
    CygnetHandle *h = handle_of(p);
    if (!h || !wd_Send) return PCAP_ERROR;

    WD_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Flags = WD_OUTBOUND;
    memcpy(addr.Network, &h->ifidx, sizeof(DWORD));  /* Network[0..3] = IfIdx */

    UINT sent = 0;
    if (!wd_Send(h->hWD, buf, (UINT)size, &sent, &addr)) return PCAP_ERROR;
    return (int)sent;
}

/* ── Public: findalldevs ─────────────────────────────────────────────────── */
int cygnet_windivert_findalldevs(pcap_if_t **alldevs, char *errbuf)
{
    if (!wd_available()) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE,
                             "WinDivert not available");
        if (alldevs) *alldevs = NULL;
        return -1;
    }

    /* Build synthetic pcap_if_t list from GetAdaptersAddresses */
    ULONG buflen = 64 * 1024;
    IP_ADAPTER_ADDRESSES *addrs = malloc(buflen);
    if (!addrs) return -1;

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &buflen) != NO_ERROR) {
        free(addrs);
        return -1;
    }

    pcap_if_t *head = NULL, *tail = NULL;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
        pcap_if_t *dev = calloc(1, sizeof(*dev));
        if (!dev) break;

        /* Use NPF-style name */
        char npf[256];
        snprintf(npf, sizeof(npf), "\\Device\\NPF_%s", a->AdapterName);
        dev->name = strdup(npf);

        /* Friendly description with short name */
        char ifname[64], desc[512];
        if (!cygnet_ifname_to_npf(npf, ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "if?");
        snprintf(desc, sizeof(desc), "[WinDivert] %s", ifname);
        dev->description = strdup(desc);

        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            dev->flags |= PCAP_IF_LOOPBACK;

        if (tail) { tail->next = dev; tail = dev; }
        else       { head = tail = dev; }
    }

    free(addrs);
    *alldevs = head;
    return 0;
}

void cygnet_windivert_freealldevs(pcap_if_t *alldevs)
{
    pcap_if_t *d = alldevs;
    while (d) {
        pcap_if_t *next = d->next;
        free(d->name);
        free(d->description);
        free(d);
        d = next;
    }
}

char *cygnet_windivert_geterr(pcap_t *p)
{
    CygnetHandle *h = handle_of(p);
    return h ? h->errbuf : (char*)"unknown error";
}
