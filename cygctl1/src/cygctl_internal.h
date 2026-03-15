/**
 * @file cygctl_internal.h
 * @brief cygctl1.dll 内部头文件
 *
 * 此文件包含 Win32 头文件，不对外暴露。
 * 只有 DLL 内部的 .c 文件可以包含此文件。
 */

#ifndef CYGCTL_INTERNAL_H
#define CYGCTL_INTERNAL_H

/* ========== Win32 头文件（隔离在此） ========== */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <mswsock.h>    /* ConnectEx */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========== 公共头文件 ========== */
#include "cygctl.h"

/* ========== 内部常量 ========== */
#define CYGCTL_MAX_INTERFACES 64
#define CYGCTL_SCAN_TIMEOUT_DEFAULT 3000
#define CYGCTL_PCAP_TIMEOUT_DEFAULT 1000

/* ========== 内部结构体 ========== */

/**
 * @brief 高性能扫描器（IOCP）
 */
struct cygctl_scanner {
    HANDLE iocp;                        /**< IOCP 句柄 */
    CRITICAL_SECTION lock;              /**< 线程锁 */
    int max_concurrent;                 /**< 最大并发数 */
    int active_count;                   /**< 当前活跃数 */
    int total_fired;                    /**< 总发起数 */
    int total_completed;                /**< 总完成数 */
    struct cygctl_scan_request* req_head; /**< 待处理请求链表（destroy 时清理用） */
};

/**
 * @brief 扫描请求（内部）
 */
struct cygctl_scan_request {
    OVERLAPPED overlapped;              /**< Win32 OVERLAPPED */
    SOCKET socket;                      /**< 套接字 */
    char ip[48];                        /**< 目标 IP */
    uint16_t port;                      /**< 目标端口 */
    int timeout_ms;                     /**< 超时时间 */
    DWORD start_time;                   /**< 开始时间 */
    struct cygctl_scan_request* next;   /**< 链表指针（用于 destroy 时清理） */
};

/**
 * @brief 原始套接字
 */
struct cygctl_raw_socket {
    SOCKET socket;                      /**< Win32 套接字 */
    int protocol;                       /**< 协议类型 */
    int af;                             /**< 地址族 (AF_INET/AF_INET6) */
};

/**
 * @brief PCAP 句柄（内部）
 */
struct cygctl_pcap {
    void* pcap_handle;                  /**< pcap_t* (不透明) */
    char errbuf[256];                   /**< 错误缓冲区 */
    int fd;                             /**< 文件描述符（如果可用） */
};

/* ========== 全局状态 ========== */
extern LPFN_CONNECTEX g_connectex;
extern int g_initialized;
extern char g_error_buf[256];

/* ========== 内部辅助函数 ========== */

/**
 * @brief 设置最后错误信息
 */
void cygctl_set_error(const char* fmt, ...);

/**
 * @brief 将 sockaddr 转换为 IP 字符串
 */
int cygctl_sockaddr_to_ip(struct sockaddr* sa, char* buf, int buf_len);

/**
 * @brief 获取 ConnectEx 函数指针
 */
int cygctl_init_connectex(void);

#endif /* CYGCTL_INTERNAL_H */
