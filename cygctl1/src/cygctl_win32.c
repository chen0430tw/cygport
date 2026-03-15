/**
 * @file cygctl_win32.c
 * @brief cygctl1.dll 核心实现 - 初始化、错误处理、网络接口
 */

#include "cygctl_internal.h"

/* ========== 全局状态 ========== */
LPFN_CONNECTEX g_connectex = NULL;
int g_initialized = 0;
char g_error_buf[256] = {0};

/* ========== 辅助函数 ========== */

void cygctl_set_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_error_buf, sizeof(g_error_buf), fmt, args);
    va_end(args);
}

int cygctl_sockaddr_to_ip(struct sockaddr* sa, char* buf, int buf_len) {
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)sa;
        return inet_ntop(AF_INET, &sin->sin_addr, buf, buf_len) ? 0 : -1;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
        return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buf_len) ? 0 : -1;
    }
    return -1;
}

int cygctl_init_connectex(void) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }

    DWORD bytes;
    GUID guid = WSAID_CONNECTEX;
    int ret = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                       &guid, sizeof(guid),
                       &g_connectex, sizeof(g_connectex),
                       &bytes, NULL, NULL);

    closesocket(s);
    return (ret == 0) ? 0 : -1;
}

/* ========== 初始化/清理 ========== */

int cygctl_init(void) {
    if (g_initialized) {
        return CYGCTL_OK;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cygctl_set_error("WSAStartup failed: %d", WSAGetLastError());
        return CYGCTL_ERROR;
    }

    if (cygctl_init_connectex() != 0) {
        cygctl_set_error("Failed to get ConnectEx function pointer");
        /* 非致命错误，继续 */
    }

    g_initialized = 1;
    return CYGCTL_OK;
}

void cygctl_cleanup(void) {
    if (g_initialized) {
        WSACleanup();
        g_initialized = 0;
        g_connectex = NULL;
    }
}

const char* cygctl_strerror(int error_code) {
    switch (error_code) {
        case CYGCTL_OK:               return "Success";
        case CYGCTL_ERROR:            return "General error";
        case CYGCTL_TIMEOUT:          return "Operation timed out";
        case CYGCTL_INVALID_HANDLE:   return "Invalid handle";
        case CYGCTL_WOULD_BLOCK:      return "Operation would block";
        case CYGCTL_NO_MEMORY:        return "Out of memory";
        case CYGCTL_INVALID_ARG:      return "Invalid argument";
        case CYGCTL_NOT_SUPPORTED:    return "Operation not supported";
        case CYGCTL_NOT_INITIALIZED:  return "Library not initialized";
        default:                      return "Unknown error";
    }
}

const char* cygctl_last_error(void) {
    return g_error_buf;
}

/* ========== 网络接口 API ========== */

int cygctl_get_interfaces(cygctl_interface_t** interfaces, int* count) {
    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 使用 GetAdaptersAddresses 获取接口信息（支持 IPv6、正确的状态检测） */
    ULONG buf_len = 15000;  /* Microsoft 推荐初始值 */
    PIP_ADAPTER_ADDRESSES adapters = malloc(buf_len);
    if (!adapters) {
        return CYGCTL_NO_MEMORY;
    }

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX  |
                  GAA_FLAG_SKIP_ANYCAST    |
                  GAA_FLAG_SKIP_MULTICAST  |
                  GAA_FLAG_SKIP_DNS_SERVER;

    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(adapters);
        adapters = malloc(buf_len);
        if (!adapters) return CYGCTL_NO_MEMORY;
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &buf_len);
    }

    if (ret != ERROR_SUCCESS) {
        free(adapters);
        cygctl_set_error("GetAdaptersAddresses failed: %lu", ret);
        return CYGCTL_ERROR;
    }

    /* 计算接口数量 */
    int n = 0;
    PIP_ADAPTER_ADDRESSES adapter = adapters;
    while (adapter && n < CYGCTL_MAX_INTERFACES) {
        n++;
        adapter = adapter->Next;
    }

    /* 分配结果数组 */
    cygctl_interface_t* result = calloc(n, sizeof(cygctl_interface_t));
    if (!result) {
        free(adapters);
        return CYGCTL_NO_MEMORY;
    }

    /* 填充接口信息 */
    adapter = adapters;
    for (int i = 0; i < n && adapter; i++) {
        /* 接口名称 (GUID 字符串) */
        strncpy(result[i].name, adapter->AdapterName, sizeof(result[i].name) - 1);

        /* MTU */
        result[i].mtu = (int)adapter->Mtu;

        /* 接口状态（精确：OperStatus 而非 DhcpEnabled） */
        result[i].is_up = (adapter->OperStatus == IfOperStatusUp) ? 1 : 0;

        /* 是否回环（精确：IfType） */
        result[i].is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) ? 1 : 0;

        /* MAC 地址 */
        if (adapter->PhysicalAddressLength == 6) {
            snprintf(result[i].mac, sizeof(result[i].mac),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     adapter->PhysicalAddress[0], adapter->PhysicalAddress[1],
                     adapter->PhysicalAddress[2], adapter->PhysicalAddress[3],
                     adapter->PhysicalAddress[4], adapter->PhysicalAddress[5]);
        } else {
            snprintf(result[i].mac, sizeof(result[i].mac), "00:00:00:00:00:00");
        }

        /* IP 地址（优先 IPv4，回退第一个 IPv6） */
        int got_ipv4 = 0;
        PIP_ADAPTER_UNICAST_ADDRESS ua = adapter->FirstUnicastAddress;
        while (ua) {
            struct sockaddr* sa = ua->Address.lpSockaddr;
            if (sa->sa_family == AF_INET && !got_ipv4) {
                struct sockaddr_in* sin4 = (struct sockaddr_in*)sa;
                inet_ntop(AF_INET, &sin4->sin_addr, result[i].ip, sizeof(result[i].ip));
                /* 前缀长度 → 点分十进制掩码 */
                UINT8 prefix = ua->OnLinkPrefixLength;
                uint32_t mask = (prefix == 0)  ? 0 :
                                (prefix == 32) ? 0xFFFFFFFF :
                                htonl(0xFFFFFFFF << (32 - prefix));
                struct in_addr maddr;
                maddr.s_addr = mask;
                inet_ntop(AF_INET, &maddr, result[i].netmask, sizeof(result[i].netmask));
                got_ipv4 = 1;
            } else if (sa->sa_family == AF_INET6 && !got_ipv4 && result[i].ip[0] == '\0') {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
                inet_ntop(AF_INET6, &sin6->sin6_addr, result[i].ip, sizeof(result[i].ip));
                snprintf(result[i].netmask, sizeof(result[i].netmask),
                         "/%u", ua->OnLinkPrefixLength);
            }
            ua = ua->Next;
        }

        if (result[i].ip[0] == '\0') {
            strncpy(result[i].ip, "0.0.0.0", sizeof(result[i].ip) - 1);
        }

        adapter = adapter->Next;
    }

    free(adapters);

    *interfaces = result;
    *count = n;
    return CYGCTL_OK;
}

void cygctl_free_interfaces(cygctl_interface_t* interfaces) {
    free(interfaces);
}

int cygctl_dnet_to_pcap(const char* dnet_name, char* pcap_name, int pcap_name_len) {
    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    if (!dnet_name || !pcap_name || pcap_name_len <= 0) {
        return CYGCTL_INVALID_ARG;
    }

    /*
     * 将 dnet 设备名（如 eth0）转换为 Npcap 设备名
     * Npcap 格式：\Device\NPF_{GUID}
     *
     * Windows 上接口名通常是 {GUID} 格式
     * 需要通过注册表或 GetAdaptersInfo 映射
     */

    /* 方法1：如果是 NPF 格式，直接返回 */
    if (strncmp(dnet_name, "\\Device\\NPF_", 12) == 0 ||
        strncmp(dnet_name, "Device/NPF_", 11) == 0) {
        strncpy(pcap_name, dnet_name, pcap_name_len - 1);
        pcap_name[pcap_name_len - 1] = '\0';
        return CYGCTL_OK;
    }

    /* 方法2：通过名称查找对应的 GUID */
    ULONG buf_len2 = 15000;
    PIP_ADAPTER_ADDRESSES adapters2 = malloc(buf_len2);
    if (!adapters2) {
        return CYGCTL_NO_MEMORY;
    }

    ULONG flags2 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD ret2 = GetAdaptersAddresses(AF_UNSPEC, flags2, NULL, adapters2, &buf_len2);
    if (ret2 == ERROR_BUFFER_OVERFLOW) {
        free(adapters2);
        adapters2 = malloc(buf_len2);
        if (!adapters2) return CYGCTL_NO_MEMORY;
        ret2 = GetAdaptersAddresses(AF_UNSPEC, flags2, NULL, adapters2, &buf_len2);
    }

    if (ret2 != ERROR_SUCCESS) {
        free(adapters2);
        cygctl_set_error("GetAdaptersAddresses failed: %lu", ret2);
        return CYGCTL_ERROR;
    }

    /* 遍历适配器查找匹配 */
    PIP_ADAPTER_ADDRESSES adapter2 = adapters2;
    int found = 0;
    int eth_index = 0;
    int target_index = -1;

    /* 解析 ethN 格式 */
    if (sscanf(dnet_name, "eth%d", &target_index) == 1) {
        /* 使用索引匹配 */
    } else if (strcmp(dnet_name, "lo") == 0 || strcmp(dnet_name, "lo0") == 0) {
        free(adapters2);
        cygctl_set_error("Loopback interface not supported");
        return CYGCTL_ERROR;
    }

    while (adapter2) {
        if (target_index >= 0) {
            if (eth_index == target_index) {
                snprintf(pcap_name, pcap_name_len, "\\Device\\NPF_%s", adapter2->AdapterName);
                found = 1;
                break;
            }
            eth_index++;
        } else {
            if (strcmp(adapter2->AdapterName, dnet_name) == 0) {
                snprintf(pcap_name, pcap_name_len, "\\Device\\NPF_%s", adapter2->AdapterName);
                found = 1;
                break;
            }
        }
        adapter2 = adapter2->Next;
    }

    free(adapters2);

    if (!found) {
        cygctl_set_error("Interface '%s' not found", dnet_name);
        return CYGCTL_ERROR;
    }

    return CYGCTL_OK;
}

/* ========== 导出 DLL 函数 ========== */

#ifdef BUILDING_DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)hModule;
    (void)reserved;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            /* 自动初始化 WSAStartup
             * 任何链接 -lcygctl1 的程序无需手动调用 WSAStartup
             * 解决 Cygwin 下 socket() 返回 -1 errno=0 的问题 */
            cygctl_init();
            break;
        case DLL_PROCESS_DETACH:
            if (g_initialized) {
                cygctl_cleanup();
            }
            break;
    }
    return TRUE;
}
#endif
