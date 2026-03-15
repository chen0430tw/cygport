/**
 * @file cygctl_pcap.c
 * @brief cygctl1.dll - PCAP 数据包捕获封装
 *
 * 封装 Npcap/wpcap 库，提供统一的捕获接口。
 * 注意：此文件使用动态加载方式，避免编译时依赖。
 */

#include "cygctl_internal.h"

/* ========== 动态加载 wpcap ========== */

/* PCAP 函数指针类型 */
typedef void* (*pcap_open_live_t)(const char*, int, int, int, char*);
typedef int (*pcap_compile_t)(void*, void*, const char*, int, unsigned int);
typedef int (*pcap_setfilter_t)(void*, void*);
typedef int (*pcap_dispatch_t)(void*, int, void*, unsigned char*);
typedef void (*pcap_close_t)(void*);
typedef char* (*pcap_geterr_t)(void*);
typedef int (*pcap_datalink_t)(void*);
typedef const unsigned char* (*pcap_next_t)(void*, void*);

/* 函数指针 */
static pcap_open_live_t fp_pcap_open_live = NULL;
static pcap_compile_t fp_pcap_compile = NULL;
static pcap_setfilter_t fp_pcap_setfilter = NULL;
static pcap_dispatch_t fp_pcap_dispatch = NULL;
static pcap_close_t fp_pcap_close = NULL;
static pcap_geterr_t fp_pcap_geterr = NULL;
static pcap_datalink_t fp_pcap_datalink = NULL;
static pcap_next_t fp_pcap_next = NULL;

static HMODULE g_wpcap_handle = NULL;
static int g_pcap_initialized = 0;

/* 加载 wpcap.dll */
static int load_wpcap(void) {
    if (g_pcap_initialized) {
        return g_wpcap_handle ? 0 : -1;
    }

    g_wpcap_handle = LoadLibraryA("wpcap.dll");
    if (!g_wpcap_handle) {
        cygctl_set_error("Failed to load wpcap.dll: %lu (Npcap installed?)", GetLastError());
        g_pcap_initialized = 1;
        return -1;
    }

    /* 获取函数指针 */
    fp_pcap_open_live = (pcap_open_live_t)GetProcAddress(g_wpcap_handle, "pcap_open_live");
    fp_pcap_compile = (pcap_compile_t)GetProcAddress(g_wpcap_handle, "pcap_compile");
    fp_pcap_setfilter = (pcap_setfilter_t)GetProcAddress(g_wpcap_handle, "pcap_setfilter");
    fp_pcap_dispatch = (pcap_dispatch_t)GetProcAddress(g_wpcap_handle, "pcap_dispatch");
    fp_pcap_close = (pcap_close_t)GetProcAddress(g_wpcap_handle, "pcap_close");
    fp_pcap_geterr = (pcap_geterr_t)GetProcAddress(g_wpcap_handle, "pcap_geterr");
    fp_pcap_datalink = (pcap_datalink_t)GetProcAddress(g_wpcap_handle, "pcap_datalink");
    fp_pcap_next = (pcap_next_t)GetProcAddress(g_wpcap_handle, "pcap_next");

    if (!fp_pcap_open_live || !fp_pcap_close) {
        cygctl_set_error("Failed to get pcap function pointers");
        FreeLibrary(g_wpcap_handle);
        g_wpcap_handle = NULL;
        g_pcap_initialized = 1;
        return -1;
    }

    g_pcap_initialized = 1;
    return 0;
}

/* ========== PCAP 结构体（内部） ========== */

struct cygctl_pcap_internal {
    void* pcap_handle;          /* pcap_t* */
    char errbuf[256];
};

/* pcap_pkthdr 结构（兼容 wpcap） */
struct pcap_pkthdr_compat {
    struct {
        unsigned long tv_sec;
        unsigned long tv_usec;
    } ts;
    unsigned int caplen;
    unsigned int len;
};

/* ========== PCAP API 实现 ========== */

cygctl_pcap_t cygctl_pcap_open(const char* device, int snaplen, int promisc, int timeout_ms) {
    if (!device) {
        return NULL;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return NULL;
    }

    if (load_wpcap() != 0) {
        return NULL;
    }

    struct cygctl_pcap_internal* p = calloc(1, sizeof(*p));
    if (!p) {
        return NULL;
    }

    /* 打开设备 */
    p->pcap_handle = fp_pcap_open_live(device, snaplen, promisc,
                                        timeout_ms > 0 ? timeout_ms : CYGCTL_PCAP_TIMEOUT_DEFAULT,
                                        p->errbuf);

    if (!p->pcap_handle) {
        cygctl_set_error("pcap_open_live failed: %s", p->errbuf);
        free(p);
        return NULL;
    }

    return p;
}

int cygctl_pcap_set_filter(cygctl_pcap_t pcap, const char* filter) {
    if (!pcap || !filter) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_pcap_internal* p = (struct cygctl_pcap_internal*)pcap;

    if (!g_wpcap_handle || !fp_pcap_compile || !fp_pcap_setfilter) {
        cygctl_set_error("wpcap not loaded");
        return CYGCTL_ERROR;
    }

    /* bpf_program 结构（兼容） */
    struct {
        unsigned int bf_len;
        void* bf_insns;
    } bpf;

    /* 编译过滤器 */
    if (fp_pcap_compile(p->pcap_handle, &bpf, filter, 1, 0) < 0) {
        cygctl_set_error("pcap_compile failed: %s", fp_pcap_geterr(p->pcap_handle));
        return CYGCTL_ERROR;
    }

    /* 设置过滤器 */
    int ret = fp_pcap_setfilter(p->pcap_handle, &bpf);
    if (ret < 0) {
        cygctl_set_error("pcap_setfilter failed: %s", fp_pcap_geterr(p->pcap_handle));
        return CYGCTL_ERROR;
    }

    return CYGCTL_OK;
}

/* 回调适配器 */
struct pcap_callback_ctx {
    cygctl_pcap_callback_t user_callback;
    void* user_data;
};

static void pcap_callback_adapter(unsigned char* user,const struct pcap_pkthdr_compat* header,
                                   const unsigned char* data) {
    struct pcap_callback_ctx* ctx = (struct pcap_callback_ctx*)user;
    if (ctx && ctx->user_callback) {
        ctx->user_callback(data, header->caplen, NULL, ctx->user_data);
    }
}

int cygctl_pcap_dispatch(cygctl_pcap_t pcap, int max_packets,
                          cygctl_pcap_callback_t callback, void* user_data) {
    if (!pcap || !callback) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_pcap_internal* p = (struct cygctl_pcap_internal*)pcap;

    if (!g_wpcap_handle || !fp_pcap_dispatch) {
        cygctl_set_error("wpcap not loaded");
        return CYGCTL_ERROR;
    }

    struct pcap_callback_ctx ctx = {
        .user_callback = callback,
        .user_data = user_data
    };

    int count = fp_pcap_dispatch(p->pcap_handle, max_packets,
                                  (void*)pcap_callback_adapter,
                                  (unsigned char*)&ctx);

    return count;
}

int cygctl_pcap_next(cygctl_pcap_t pcap, void* buffer, size_t max_len) {
    if (!pcap || !buffer || max_len == 0) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_pcap_internal* p = (struct cygctl_pcap_internal*)pcap;

    if (!g_wpcap_handle || !fp_pcap_next) {
        cygctl_set_error("wpcap not loaded");
        return CYGCTL_ERROR;
    }

    struct pcap_pkthdr_compat header;
    const unsigned char* data = fp_pcap_next(p->pcap_handle, &header);

    if (!data) {
        return 0;  /* 超时或无数据 */
    }

    size_t copy_len = header.caplen < max_len ? header.caplen : max_len;
    memcpy(buffer, data, copy_len);

    return (int)copy_len;
}

void cygctl_pcap_close(cygctl_pcap_t pcap) {
    if (!pcap) {
        return;
    }

    struct cygctl_pcap_internal* p = (struct cygctl_pcap_internal*)pcap;

    if (p->pcap_handle && fp_pcap_close) {
        fp_pcap_close(p->pcap_handle);
    }

    free(p);
}

const char* cygctl_pcap_geterr(cygctl_pcap_t pcap) {
    if (!pcap) {
        return "NULL pcap handle";
    }

    struct cygctl_pcap_internal* p = (struct cygctl_pcap_internal*)pcap;

    if (fp_pcap_geterr && p->pcap_handle) {
        return fp_pcap_geterr(p->pcap_handle);
    }

    return p->errbuf;
}
