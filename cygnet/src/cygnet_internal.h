/*
 * cygnet_internal.h — Internal interfaces between cygnet modules
 */
#pragma once

#include <pcap.h>
#include "../include/cygnet.h"

/* ── ifname.c ────────────────────────────────────────────────────────────── */
void cygnet_ifname_dump(void);   /* debug: print full interface map */

/* ── npcap_loader.c ─────────────────────────────────────────────────────── */
/* Used by ifname.c to enumerate Npcap devices during cache build */
int  cygnet_npcap_pcap_findalldevs(pcap_if_t **alldevs, char *errbuf);
void cygnet_npcap_pcap_freealldevs(pcap_if_t *alldevs);

/* ── windivert_pcap.c ────────────────────────────────────────────────────── */
/*
 * WinDivert-based fallback implementations.
 * Called by npcap_loader.c when Npcap is not available.
 * Phase 2 implementation — stubs provided here for now.
 */
pcap_t *cygnet_windivert_open      (const char*, int, int, int, char*);
int     cygnet_windivert_set_snaplen  (pcap_t*, int);
int     cygnet_windivert_set_promisc  (pcap_t*, int);
int     cygnet_windivert_set_timeout  (pcap_t*, int);
int     cygnet_windivert_set_imm_mode (pcap_t*, int);
int     cygnet_windivert_activate     (pcap_t*);
void    cygnet_windivert_close        (pcap_t*);
int     cygnet_windivert_compile      (pcap_t*, struct bpf_program*, const char*, int, bpf_u_int32);
int     cygnet_windivert_setfilter    (pcap_t*, struct bpf_program*);
int     cygnet_windivert_next_ex      (pcap_t*, struct pcap_pkthdr**, const u_char**);
int     cygnet_windivert_dispatch     (pcap_t*, int, pcap_handler, u_char*);
void    cygnet_windivert_breakloop    (pcap_t*);
int     cygnet_windivert_inject       (pcap_t*, const void*, int);
int     cygnet_windivert_findalldevs  (pcap_if_t**, char*);
void    cygnet_windivert_freealldevs  (pcap_if_t*);
char   *cygnet_windivert_geterr       (pcap_t*);
