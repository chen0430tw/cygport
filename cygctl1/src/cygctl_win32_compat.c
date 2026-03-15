/**
 * @file cygctl_win32_compat.c
 * @brief WIN32 兼容层实现 - 提供 WIN32 函数的 Cygwin 版本
 *
 * 此文件提供 nmap 等工具在 WIN32 代码块中声明的函数的实现。
 * 链接时会优先使用这些实现，而不是依赖原始的 WIN32 实现。
 *
 * 编译：gcc -c cygctl_win32_compat.c -o cygctl_win32_compat.o
 * 链接：将 cygctl_win32_compat.o 放在链接命令中
 */

#include "cygctl.h"
#include <string.h>

/* 全局初始化标志 */
static int g_cygctl_compat_initialized = 0;

/* 确保 cygctl 已初始化 */
static void ensure_initialized(void) {
    if (!g_cygctl_compat_initialized) {
        cygctl_init();
        g_cygctl_compat_initialized = 1;
    }
}

/**
 * @brief 将 dnet 设备名转换为 pcap 设备名
 *
 * 这是 nmap 在 WIN32 下使用的函数。
 * 我们提供一个 Cygwin 版本，内部调用 cygctl API。
 *
 * @param dnetdev dnet 设备名 (e.g., "eth0")
 * @param pcapdev 输出缓冲区
 * @param pcapdevlen 缓冲区长度
 * @return 1 成功，0 失败
 */
int DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen) {
    ensure_initialized();

    if (!dnetdev || !pcapdev || pcapdevlen <= 0) {
        return 0;
    }

    /* 调用 cygctl API */
    if (cygctl_dnet_to_pcap(dnetdev, pcapdev, pcapdevlen) == CYGCTL_OK) {
        return 1;
    }

    /* 失败，复制原始名称 */
    strncpy(pcapdev, dnetdev, pcapdevlen - 1);
    pcapdev[pcapdevlen - 1] = '\0';
    return 0;
}

/**
 * @brief 将 pcap 设备名转换为 dnet 设备名
 *
 * @param pcapdev pcap 设备名
 * @param dnetdev 输出缓冲区
 * @param dnetdevlen 缓冲区长度
 * @return 1 成功，0 失败
 */
int PcapName2DnetName(const char *pcapdev, char *dnetdev, int dnetdevlen) {
    ensure_initialized();

    if (!pcapdev || !dnetdev || dnetdevlen <= 0) {
        return 0;
    }

    /* 检查是否已经是 dnet 格式 */
    if (strncmp(pcapdev, "\\Device\\NPF_", 12) != 0) {
        /* 不是 NPF 格式，直接复制 */
        strncpy(dnetdev, pcapdev, dnetdevlen - 1);
        dnetdev[dnetdevlen - 1] = '\0';
        return 1;
    }

    /* 从 NPF 名称提取索引 */
    /* 简化处理：返回 eth0 */
    strncpy(dnetdev, "eth0", dnetdevlen - 1);
    dnetdev[dnetdevlen - 1] = '\0';
    return 1;
}

/**
 * @brief 获取可选择的 pcap 文件描述符
 *
 * Npcap 不支持 pcap_get_selectable_fd()，返回 -1。
 * 这告诉 nmap 使用轮询模式。
 *
 * @param p pcap 句柄
 * @return -1（不可选择）
 */
int my_pcap_get_selectable_fd(void *p) {
    (void)p;
    return -1;
}

/**
 * @brief 检查 pcap_selectable_fd 是否有效
 *
 * @return 0（无效）
 */
int pcap_selectable_fd_valid(void) {
    return 0;
}
