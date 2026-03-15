/*
 * packet_shim.c — Full Packet.dll proxy shim (no macros, plain C)
 *
 * Compiled with MinGW-w64. Installed to /usr/local/bin/ so Windows
 * loader picks it up before C:\Windows\System32\Npcap\Packet.dll.
 * PacketOpenAdapter runs in a thread with a 5-second timeout.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Use void* for LPADAPTER/LPPACKET — avoids needing Npcap headers */
typedef void* LPADAPTER;
typedef void* LPPACKET;

/* ── Real Packet.dll ─────────────────────────────────────────────────────── */
static HMODULE hReal = NULL;

static void shim_log(const char *msg)
{
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, msg, (DWORD)strlen(msg), &w, NULL);
    }
}

/* Function pointers to real Packet.dll */
static LPADAPTER (WINAPI *real_PacketOpenAdapter)(PCCH);
static void      (WINAPI *real_PacketCloseAdapter)(LPADAPTER);
static BOOL      (WINAPI *real_PacketSendPacket)(LPADAPTER, LPPACKET, BOOL);
static int       (WINAPI *real_PacketSendPackets)(LPADAPTER, PVOID, ULONG, BOOL);
static BOOL      (WINAPI *real_PacketReceivePacket)(LPADAPTER, LPPACKET, BOOL);
static BOOL      (WINAPI *real_PacketRequest)(LPADAPTER, BOOL, PVOID);
static BOOL      (WINAPI *real_PacketGetInfo)(LPADAPTER, PVOID);
static BOOL      (WINAPI *real_PacketGetNetType)(LPADAPTER, PVOID);
static BOOL      (WINAPI *real_PacketSetMinToCopy)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketSetNumWrites)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketSetMode)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketSetReadTimeout)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketSetBpf)(LPADAPTER, PVOID);
static BOOL      (WINAPI *real_PacketSetLoopbackBehavior)(LPADAPTER, UINT);
static BOOL      (WINAPI *real_PacketSetTimestampMode)(LPADAPTER, ULONG);
static BOOL      (WINAPI *real_PacketGetTimestampModes)(LPADAPTER, PULONG);
static int       (WINAPI *real_PacketSetSnapLen)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketGetStats)(LPADAPTER, PVOID);
static BOOL      (WINAPI *real_PacketGetStatsEx)(LPADAPTER, PVOID);
static BOOL      (WINAPI *real_PacketSetBuff)(LPADAPTER, int);
static BOOL      (WINAPI *real_PacketSetHwFilter)(LPADAPTER, ULONG);
static HANDLE    (WINAPI *real_PacketGetReadEvent)(LPADAPTER);
static LPPACKET  (WINAPI *real_PacketAllocatePacket)(void);
static void      (WINAPI *real_PacketInitPacket)(LPPACKET, PVOID, UINT);
static void      (WINAPI *real_PacketFreePacket)(LPPACKET);
static BOOL      (WINAPI *real_PacketGetAdapterNames)(PCHAR, PULONG);
static BOOL      (WINAPI *real_PacketGetNetInfoEx)(PCCH, PVOID, PLONG);
static BOOL      (WINAPI *real_PacketIsLoopbackAdapter)(PCCH);
static int       (WINAPI *real_PacketIsMonitorModeSupported)(PCCH);
static int       (WINAPI *real_PacketSetMonitorMode)(PCCH, int);
static int       (WINAPI *real_PacketGetMonitorMode)(PCCH);
static LPCSTR    (WINAPI *real_PacketGetVersion)(void);
static LPCSTR    (WINAPI *real_PacketGetDriverVersion)(void);
static LPCSTR    (WINAPI *real_PacketGetDriverName)(void);
static BOOL      (WINAPI *real_PacketStopDriver)(void);
static BOOL      (WINAPI *real_PacketStopDriver60)(void);
static BOOL      (WINAPI *real_PacketSetDumpName)(LPADAPTER, void*, int);
static BOOL      (WINAPI *real_PacketSetDumpLimits)(LPADAPTER, UINT, UINT);
static BOOL      (WINAPI *real_PacketIsDumpEnded)(LPADAPTER, BOOL);
static PVOID     (WINAPI *real_PacketGetAirPcapHandle)(LPADAPTER);

#define GP(field) real_##field = (void*)GetProcAddress(hReal, #field)

static void load_real(void)
{
    if (hReal) return;
    hReal = LoadLibraryA("C:\\Windows\\System32\\Npcap\\Packet.dll");
    if (!hReal) { shim_log("[Packet.shim] ERROR: cannot load real Packet.dll\n"); return; }
    /* Packet.dll loaded — no log needed in production */
    GP(PacketOpenAdapter);       GP(PacketCloseAdapter);
    GP(PacketSendPacket);        GP(PacketSendPackets);
    GP(PacketReceivePacket);     GP(PacketRequest);
    GP(PacketGetInfo);           GP(PacketGetNetType);
    GP(PacketSetMinToCopy);      GP(PacketSetNumWrites);
    GP(PacketSetMode);           GP(PacketSetReadTimeout);
    GP(PacketSetBpf);            GP(PacketSetLoopbackBehavior);
    GP(PacketSetTimestampMode);  GP(PacketGetTimestampModes);
    GP(PacketSetSnapLen);        GP(PacketGetStats);
    GP(PacketGetStatsEx);        GP(PacketSetBuff);
    GP(PacketSetHwFilter);       GP(PacketGetReadEvent);
    GP(PacketAllocatePacket);    GP(PacketInitPacket);
    GP(PacketFreePacket);        GP(PacketGetAdapterNames);
    GP(PacketGetNetInfoEx);      GP(PacketIsLoopbackAdapter);
    GP(PacketIsMonitorModeSupported); GP(PacketSetMonitorMode);
    GP(PacketGetMonitorMode);    GP(PacketGetVersion);
    GP(PacketGetDriverVersion);  GP(PacketGetDriverName);
    GP(PacketStopDriver);        GP(PacketStopDriver60);
    GP(PacketSetDumpName);       GP(PacketSetDumpLimits);
    GP(PacketIsDumpEnded);       GP(PacketGetAirPcapHandle);
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD reason, LPVOID reserved)
{
    (void)hMod; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hMod); load_real(); }
    return TRUE;
}

/* ── PacketOpenAdapter with 5-second timeout ─────────────────────────────── */
typedef struct { PCCH name; LPADAPTER result; } OpenArg;
static DWORD WINAPI open_thread(LPVOID arg) {
    OpenArg *a = (OpenArg*)arg;
    a->result = real_PacketOpenAdapter(a->name);
    return 0;
}
LPADAPTER WINAPI PacketOpenAdapter(PCCH adapterName)
{
    load_real();
    if (!real_PacketOpenAdapter) return NULL;

    OpenArg arg = { adapterName, NULL };
    HANDLE ht = CreateThread(NULL, 0, open_thread, &arg, 0, NULL);
    if (!ht) { arg.result = real_PacketOpenAdapter(adapterName); goto done; }
    if (WaitForSingleObject(ht, 5000) == WAIT_TIMEOUT) {
        shim_log("[Packet.shim] PacketOpenAdapter: TIMEOUT — hung!\n");
        TerminateThread(ht, 1); CloseHandle(ht); return NULL;
    }
    CloseHandle(ht);
done:
    return arg.result;
}

/* ── All other forwards ──────────────────────────────────────────────────── */
void WINAPI PacketCloseAdapter(LPADAPTER a)
    { load_real(); if (real_PacketCloseAdapter) real_PacketCloseAdapter(a); }
BOOL WINAPI PacketSendPacket(LPADAPTER a, LPPACKET p, BOOL s)
    { load_real(); return real_PacketSendPacket ? real_PacketSendPacket(a,p,s) : FALSE; }
int WINAPI PacketSendPackets(LPADAPTER a, PVOID b, ULONG sz, BOOL s)
    { load_real(); return real_PacketSendPackets ? real_PacketSendPackets(a,b,sz,s) : 0; }
BOOL WINAPI PacketReceivePacket(LPADAPTER a, LPPACKET p, BOOL s)
    { load_real(); return real_PacketReceivePacket ? real_PacketReceivePacket(a,p,s) : FALSE; }
BOOL WINAPI PacketRequest(LPADAPTER a, BOOL set, PVOID oid)
    { load_real(); return real_PacketRequest ? real_PacketRequest(a,set,oid) : FALSE; }
BOOL WINAPI PacketGetInfo(LPADAPTER a, PVOID oid)
    { load_real(); return real_PacketGetInfo ? real_PacketGetInfo(a,oid) : FALSE; }
BOOL WINAPI PacketGetNetType(LPADAPTER a, PVOID t)
    { load_real(); return real_PacketGetNetType ? real_PacketGetNetType(a,t) : FALSE; }
BOOL WINAPI PacketSetMinToCopy(LPADAPTER a, int n)
    { load_real(); return real_PacketSetMinToCopy ? real_PacketSetMinToCopy(a,n) : FALSE; }
BOOL WINAPI PacketSetNumWrites(LPADAPTER a, int n)
    { load_real(); return real_PacketSetNumWrites ? real_PacketSetNumWrites(a,n) : FALSE; }
BOOL WINAPI PacketSetMode(LPADAPTER a, int m)
    { load_real(); return real_PacketSetMode ? real_PacketSetMode(a,m) : FALSE; }
BOOL WINAPI PacketSetReadTimeout(LPADAPTER a, int t)
    { load_real(); return real_PacketSetReadTimeout ? real_PacketSetReadTimeout(a,t) : FALSE; }
BOOL WINAPI PacketSetBpf(LPADAPTER a, PVOID fp)
    { load_real(); return real_PacketSetBpf ? real_PacketSetBpf(a,fp) : FALSE; }
BOOL WINAPI PacketSetLoopbackBehavior(LPADAPTER a, UINT b)
    { load_real(); return real_PacketSetLoopbackBehavior ? real_PacketSetLoopbackBehavior(a,b) : FALSE; }
BOOL WINAPI PacketSetTimestampMode(LPADAPTER a, ULONG m)
    { load_real(); return real_PacketSetTimestampMode ? real_PacketSetTimestampMode(a,m) : FALSE; }
BOOL WINAPI PacketGetTimestampModes(LPADAPTER a, PULONG m)
    { load_real(); return real_PacketGetTimestampModes ? real_PacketGetTimestampModes(a,m) : FALSE; }
int WINAPI PacketSetSnapLen(LPADAPTER a, int n)
    { load_real(); return real_PacketSetSnapLen ? real_PacketSetSnapLen(a,n) : 0; }
BOOL WINAPI PacketGetStats(LPADAPTER a, PVOID s)
    { load_real(); return real_PacketGetStats ? real_PacketGetStats(a,s) : FALSE; }
BOOL WINAPI PacketGetStatsEx(LPADAPTER a, PVOID s)
    { load_real(); return real_PacketGetStatsEx ? real_PacketGetStatsEx(a,s) : FALSE; }
BOOL WINAPI PacketSetBuff(LPADAPTER a, int d)
    { load_real(); return real_PacketSetBuff ? real_PacketSetBuff(a,d) : FALSE; }
BOOL WINAPI PacketSetHwFilter(LPADAPTER a, ULONG f)
    { load_real(); return real_PacketSetHwFilter ? real_PacketSetHwFilter(a,f) : FALSE; }
HANDLE WINAPI PacketGetReadEvent(LPADAPTER a)
    { load_real(); return real_PacketGetReadEvent ? real_PacketGetReadEvent(a) : NULL; }
LPPACKET WINAPI PacketAllocatePacket(void)
    { load_real(); return real_PacketAllocatePacket ? real_PacketAllocatePacket() : NULL; }
void WINAPI PacketInitPacket(LPPACKET p, PVOID buf, UINT len)
    { load_real(); if (real_PacketInitPacket) real_PacketInitPacket(p,buf,len); }
void WINAPI PacketFreePacket(LPPACKET p)
    { load_real(); if (real_PacketFreePacket) real_PacketFreePacket(p); }
BOOL WINAPI PacketGetAdapterNames(PCHAR s, PULONG sz)
    { load_real(); return real_PacketGetAdapterNames ? real_PacketGetAdapterNames(s,sz) : FALSE; }
BOOL WINAPI PacketGetNetInfoEx(PCCH name, PVOID buf, PLONG n)
    { load_real(); return real_PacketGetNetInfoEx ? real_PacketGetNetInfoEx(name,buf,n) : FALSE; }
BOOL WINAPI PacketIsLoopbackAdapter(PCCH name)
    { load_real(); return real_PacketIsLoopbackAdapter ? real_PacketIsLoopbackAdapter(name) : FALSE; }
int WINAPI PacketIsMonitorModeSupported(PCCH name)
    { load_real(); return real_PacketIsMonitorModeSupported ? real_PacketIsMonitorModeSupported(name) : 0; }
int WINAPI PacketSetMonitorMode(PCCH name, int m)
    { load_real(); return real_PacketSetMonitorMode ? real_PacketSetMonitorMode(name,m) : 0; }
int WINAPI PacketGetMonitorMode(PCCH name)
    { load_real(); return real_PacketGetMonitorMode ? real_PacketGetMonitorMode(name) : 0; }
LPCSTR WINAPI PacketGetVersion(void)
    { load_real(); return real_PacketGetVersion ? real_PacketGetVersion() : "shim-0.1"; }
LPCSTR WINAPI PacketGetDriverVersion(void)
    { load_real(); return real_PacketGetDriverVersion ? real_PacketGetDriverVersion() : "shim-0.1"; }
LPCSTR WINAPI PacketGetDriverName(void)
    { load_real(); return real_PacketGetDriverName ? real_PacketGetDriverName() : "npcap"; }
BOOL WINAPI PacketStopDriver(void)
    { load_real(); return real_PacketStopDriver ? real_PacketStopDriver() : FALSE; }
BOOL WINAPI PacketStopDriver60(void)
    { load_real(); return real_PacketStopDriver60 ? real_PacketStopDriver60() : FALSE; }
BOOL WINAPI PacketSetDumpName(LPADAPTER a, void* name, int len)
    { load_real(); return real_PacketSetDumpName ? real_PacketSetDumpName(a,name,len) : FALSE; }
BOOL WINAPI PacketSetDumpLimits(LPADAPTER a, UINT mf, UINT mn)
    { load_real(); return real_PacketSetDumpLimits ? real_PacketSetDumpLimits(a,mf,mn) : FALSE; }
BOOL WINAPI PacketIsDumpEnded(LPADAPTER a, BOOL s)
    { load_real(); return real_PacketIsDumpEnded ? real_PacketIsDumpEnded(a,s) : FALSE; }
PVOID WINAPI PacketGetAirPcapHandle(LPADAPTER a)
    { load_real(); return real_PacketGetAirPcapHandle ? real_PacketGetAirPcapHandle(a) : NULL; }
