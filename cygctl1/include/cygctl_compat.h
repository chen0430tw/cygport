/**
 * @file cygctl_compat.h
 * @brief Cygwin 移植兼容层 - 缺失 POSIX/GNU 函数补全
 *
 * Linux 程序移植到 Cygwin 时，只需在编译命令加：
 *   -I/path/to/cygctl/include
 * 并在源文件顶部 include：
 *   #include <cygctl_compat.h>
 *
 * 涵盖内容：
 *   - 缺失的 GNU 扩展字符串函数（strcasestr, strndup 等）
 *   - 缺失的 POSIX 网络常量（IPV6_* 等）
 *   - wpcap/libpcap 名称统一
 *   - 其他 Cygwin 已知缺陷的补丁
 *
 * @version 1.1
 * @date 2026-03-13
 */

#ifndef CYGCTL_COMPAT_H
#define CYGCTL_COMPAT_H

#ifdef __CYGWIN__

#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================
 * 字符串函数补全
 * ======================================================== */

/**
 * strcasestr — 大小写不敏感的子串搜索
 * Cygwin 的 string.h 不提供此 GNU 扩展
 */
#ifndef CYGCTL_COMPAT_HAVE_STRCASESTR
#define CYGCTL_COMPAT_HAVE_STRCASESTR
static inline const char *strcasestr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack, *n = needle;
            while (*h && *n &&
                   tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++; n++;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}
#endif

/* strndup: Cygwin 3.x 已内建，不需要补全 */

/**
 * memmem — 内存块子串搜索
 * Cygwin 的 string.h 不提供此 GNU 扩展
 */
#ifndef CYGCTL_COMPAT_HAVE_MEMMEM
#define CYGCTL_COMPAT_HAVE_MEMMEM
static inline void *memmem(const void *haystack, size_t haystacklen,
                            const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needlelen) == 0)
            return (void *)(h + i);
    }
    return NULL;
}
#endif

/* ========================================================
 * 网络常量补全（Cygwin 缺失的 IPv6 socket 选项）
 * ======================================================== */

#ifndef IPV6_DSTOPTS
#define IPV6_DSTOPTS    25
#endif
#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS    22
#endif
#ifndef IPV6_RTHDR
#define IPV6_RTHDR      20
#endif
#ifndef IPV6_TCLASS
#define IPV6_TCLASS     67
#endif
#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT   21
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO 49
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO    50
#endif

/* ========================================================
 * pcap / wpcap 名称统一
 * Linux 程序链接 -lpcap，Cygwin/Windows 实际库是 wpcap
 * 通过 Makefile 的 PCAP_LIBS 变量解决，但这里提供头文件级别的兼容
 * ======================================================== */

/* pcap_get_selectable_fd: Npcap 不支持，返回固定值 -1
 * __has_include 保护：全局 -include 注入时，没有 pcap 的 TU 不触发 pcap.h */
#if defined(__has_include) && __has_include(<pcap.h>)
#ifndef CYGCTL_COMPAT_HAVE_PCAP_SELECTABLE
#define CYGCTL_COMPAT_HAVE_PCAP_SELECTABLE
#include <pcap.h>
static inline int pcap_get_selectable_fd_compat(pcap_t *p) {
    (void)p;
    return -1;
}
/* 如果程序调用了 pcap_get_selectable_fd，重定向到兼容版本 */
#ifndef pcap_get_selectable_fd
#define pcap_get_selectable_fd(p) pcap_get_selectable_fd_compat(p)
#endif
#endif
#endif /* __has_include(<pcap.h>) */

/* ========================================================
 * WSAStartup 自动初始化
 *
 * 通过 __attribute__((constructor)) 在 main() 之前自动调用。
 * 解决 Cygwin 下 socket() 返回 -1 errno=0 的问题。
 *
 * ⚠️  全局 -include 注入场景下不启用：
 *   - configure 测试程序会被 dlfcn.h 影响，导致 AC_CHECK_FUNC 误判
 *   - 链接 cygctl1.dll 时，DllMain 已处理 WSAStartup，此 constructor 冗余
 *
 * 仅在明确定义 CYGCTL_ENABLE_WSA_INIT 时启用（单文件手动 include 场景）
 * ======================================================== */

#ifdef CYGCTL_ENABLE_WSA_INIT
#include <dlfcn.h>

__attribute__((constructor))
static void cygctl_auto_wsa_init(void) {
    void *hWs2 = dlopen("ws2_32.dll", RTLD_LAZY);
    if (hWs2) {
        typedef int (*WSAStartup_t)(unsigned short, void *);
        WSAStartup_t fn = (WSAStartup_t)(void *)dlsym(hWs2, "WSAStartup");
        if (fn) {
            /* WSADATA 结构体足够大的缓冲区，避免包含 winsock2.h */
            static unsigned char wsadata[512];
            fn(0x0202, wsadata);
        }
        /* 不 dlclose：WinSock 需要在整个进程生命周期内保持初始化 */
    }
}
#endif /* CYGCTL_ENABLE_WSA_INIT */

/* ========================================================
 * 其他杂项补全
 * ======================================================== */

/* Linux 的 __attribute__((unused)) 在 MSVC 没有，Cygwin 的 GCC 支持 */
#ifndef __unused
#define __unused __attribute__((unused))
#endif

/* err.h — Cygwin 有但部分老版本缺失 */
#ifndef CYGCTL_COMPAT_HAVE_ERR
#include <errno.h>
#include <stdio.h>
static inline void err_compat(int eval, const char *fmt, ...) {
    (void)eval; (void)fmt;
}
#endif

#endif /* __CYGWIN__ */

#endif /* CYGCTL_COMPAT_H */
