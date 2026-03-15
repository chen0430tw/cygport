/**
 * @file cygctl_win32_compat.h
 * @brief WIN32 兼容层 - 让 Cygwin 自动获得 WIN32 功能
 *
 * 使用方法：
 * 1. 在编译时添加 -include cygctl_win32_compat.h
 * 2. 或在源码顶部 #include "cygctl_win32_compat.h"
 *
 * 此文件会在 Cygwin 下自动定义 WIN32，使原始 WIN32 代码路径生效。
 * 然后 cygctl1.dll 会拦截相关调用并提供实现。
 */

#ifndef CYGCTL_WIN32_COMPAT_H
#define CYGCTL_WIN32_COMPAT_H

#ifdef __CYGWIN__

/* 在 Cygwin 下定义 WIN32，让原始 WIN32 代码路径生效 */
#ifndef WIN32
#define WIN32 1
#endif

/* 同时定义 _WIN32 和 _WIN64（如果需要） */
#ifndef _WIN32
#define _WIN32 1
#endif

#if defined(__x86_64__) || defined(__amd64__)
#ifndef _WIN64
#define _WIN64 1
#endif
#endif

/*
 * 关键：拦截 DnetName2PcapName 和 PcapName2DnetName
 *
 * 原始 nmap 代码：
 *   #ifdef WIN32
 *   int DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen);
 *   #endif
 *
 * 现在因为定义了 WIN32，这个函数会被声明。
 * 我们需要提供一个使用 cygctl 的实现。
 */

#include "cygctl.h"

/* 内联包装函数 - 将 Win32 风格调用转发到 cygctl */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * 设备名转换函数
 * 这些函数会被 nmap 的 WIN32 代码调用
 * 内部转发到 cygctl API
 */
static inline int _cygctl_dnet_to_pcap_wrapper(const char *dnetdev, char *pcapdev, int pcapdevlen) {
    /* 确保 cygctl 已初始化 */
    static int _cygctl_initialized = 0;
    if (!_cygctl_initialized) {
        cygctl_init();
        _cygctl_initialized = 1;
    }
    return cygctl_dnet_to_pcap(dnetdev, pcapdev, pcapdevlen) == CYGCTL_OK ? 1 : 0;
}

/* 定义别名，让 WIN32 代码调用我们的包装函数 */
#define DnetName2PcapName(dnetdev, pcapdev, pcapdevlen) \
    _cygctl_dnet_to_pcap_wrapper((dnetdev), (pcapdev), (pcapdevlen))

#ifdef __cplusplus
}
#endif

#endif /* __CYGWIN__ */

#endif /* CYGCTL_WIN32_COMPAT_H */
