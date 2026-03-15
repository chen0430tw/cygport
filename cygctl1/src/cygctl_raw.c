/**
 * @file cygctl_raw.c
 * @brief cygctl1.dll - 原始套接字实现
 *
 * 提供原始套接字功能，用于 ICMP、自定义 TCP/UDP 等操作。
 * 注意：需要管理员权限。
 */

#include "cygctl_internal.h"

/* ========== 原始套接字创建/关闭 ========== */

cygctl_socket_t cygctl_raw_socket(int protocol) {
    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return NULL;
    }

    int win_proto;
    switch (protocol) {
        case CYGCTL_PROTO_ICMP:
            win_proto = IPPROTO_ICMP;
            break;
        case CYGCTL_PROTO_TCP:
            win_proto = IPPROTO_TCP;
            break;
        case CYGCTL_PROTO_UDP:
            win_proto = IPPROTO_UDP;
            break;
        default:
            cygctl_set_error("Unsupported protocol: %d", protocol);
            return NULL;
    }

    SOCKET sock = socket(AF_INET, SOCK_RAW, win_proto);
    if (sock == INVALID_SOCKET) {
        /* 可能需要管理员权限 */
        DWORD err = WSAGetLastError();
        cygctl_set_error("socket(SOCK_RAW) failed: %d (requires admin?)", err);
        return NULL;
    }

    struct cygctl_raw_socket* s = calloc(1, sizeof(*s));
    if (!s) {
        closesocket(sock);
        return NULL;
    }

    s->socket = sock;
    s->protocol = protocol;
    s->af = AF_INET;

    return s;
}

void cygctl_raw_close(cygctl_socket_t sock) {
    if (!sock) {
        return;
    }

    struct cygctl_raw_socket* s = (struct cygctl_raw_socket*)sock;

    if (s->socket != INVALID_SOCKET) {
        closesocket(s->socket);
    }

    free(s);
}

/* ========== 发送原始数据 ========== */

int cygctl_raw_send(cygctl_socket_t sock,
                     const void* data,
                     size_t len,
                     const char* dest_ip) {
    if (!sock) {
        return CYGCTL_INVALID_HANDLE;
    }

    if (!data || len == 0 || !dest_ip) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_raw_socket* s = (struct cygctl_raw_socket*)sock;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;  /* 原始套接字不使用端口 */

    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) != 1) {
        cygctl_set_error("Invalid IP address: %s", dest_ip);
        return CYGCTL_INVALID_ARG;
    }

    int sent = sendto(s->socket, (const char*)data, (int)len, 0,
                      (struct sockaddr*)&dest, sizeof(dest));

    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        cygctl_set_error("sendto failed: %d", err);
        return CYGCTL_ERROR;
    }

    return sent;
}

/* ========== 接收原始数据 ========== */

int cygctl_raw_recv(cygctl_socket_t sock,
                     void* buffer,
                     size_t max_len,
                     char* src_ip,
                     int timeout_ms) {
    if (!sock) {
        return CYGCTL_INVALID_HANDLE;
    }

    if (!buffer || max_len == 0) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_raw_socket* s = (struct cygctl_raw_socket*)sock;

    /* 设置接收超时 */
    if (timeout_ms > 0) {
        DWORD tv = timeout_ms;
        if (setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO,
                       (const char*)&tv, sizeof(tv)) == SOCKET_ERROR) {
            cygctl_set_error("setsockopt(SO_RCVTIMEO) failed: %d", WSAGetLastError());
            /* 非致命，继续 */
        }
    }

    struct sockaddr_in src;
    int src_len = sizeof(src);
    memset(&src, 0, sizeof(src));

    int received = recvfrom(s->socket, (char*)buffer, (int)max_len, 0,
                            (struct sockaddr*)&src, &src_len);

    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
            return 0;  /* 超时 */
        }
        cygctl_set_error("recvfrom failed: %d", err);
        return CYGCTL_ERROR;
    }

    /* 返回源 IP */
    if (src_ip) {
        inet_ntop(AF_INET, &src.sin_addr, src_ip, 48);
    }

    return received;
}

/* ========== ARP 操作 ========== */

int cygctl_arp_get(const char* ip, char* out_mac) {
    if (!ip || !out_mac) {
        return CYGCTL_INVALID_ARG;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 解析 IP */
    IPAddr dest_ip;
    if (inet_pton(AF_INET, ip, &dest_ip) != 1) {
        cygctl_set_error("Invalid IP address: %s", ip);
        return CYGCTL_INVALID_ARG;
    }

    /* 获取 ARP 表 */
    ULONG buf_len = 0;
    GetIpNetTable(NULL, &buf_len, FALSE);

    if (buf_len == 0) {
        cygctl_set_error("ARP table is empty");
        return CYGCTL_ERROR;
    }

    PMIB_IPNETTABLE arp_table = malloc(buf_len);
    if (!arp_table) {
        return CYGCTL_NO_MEMORY;
    }

    if (GetIpNetTable(arp_table, &buf_len, FALSE) != NO_ERROR) {
        free(arp_table);
        cygctl_set_error("GetIpNetTable failed");
        return CYGCTL_ERROR;
    }

    /* 查找匹配的 IP */
    for (DWORD i = 0; i < arp_table->dwNumEntries; i++) {
        if (arp_table->table[i].dwAddr == dest_ip) {
            /* 找到，格式化 MAC 地址 */
            snprintf(out_mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                     arp_table->table[i].bPhysAddr[0],
                     arp_table->table[i].bPhysAddr[1],
                     arp_table->table[i].bPhysAddr[2],
                     arp_table->table[i].bPhysAddr[3],
                     arp_table->table[i].bPhysAddr[4],
                     arp_table->table[i].bPhysAddr[5]);
            free(arp_table);
            return CYGCTL_OK;
        }
    }

    free(arp_table);
    cygctl_set_error("IP %s not found in ARP table", ip);
    return CYGCTL_ERROR;
}

int cygctl_arp_set(const char* ip, const char* mac) {
    if (!ip || !mac) {
        return CYGCTL_INVALID_ARG;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 解析 IP */
    IPAddr dest_ip;
    if (inet_pton(AF_INET, ip, &dest_ip) != 1) {
        cygctl_set_error("Invalid IP address: %s", ip);
        return CYGCTL_INVALID_ARG;
    }

    /* 解析 MAC */
    unsigned char mac_bytes[6];
    if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) != 6) {
        cygctl_set_error("Invalid MAC address format: %s", mac);
        return CYGCTL_INVALID_ARG;
    }

    /* 查找最佳接口索引 */
    DWORD best_if_index = 0;
    if (GetBestInterface(dest_ip, &best_if_index) != NO_ERROR) {
        cygctl_set_error("GetBestInterface failed for IP %s", ip);
        return CYGCTL_ERROR;
    }

    /* 添加静态 ARP 表项 */
    MIB_IPNETROW row;
    memset(&row, 0, sizeof(row));
    row.dwIndex = best_if_index;  /* 修复：原为硬编码 0，导致 SetIpNetEntry 失败 */
    row.dwPhysAddrLen = 6;
    memcpy(row.bPhysAddr, mac_bytes, 6);
    row.dwAddr = dest_ip;
    row.dwType = MIB_IPNET_TYPE_STATIC;

    DWORD ret = SetIpNetEntry(&row);
    if (ret != NO_ERROR) {
        cygctl_set_error("SetIpNetEntry failed: %lu", ret);
        return CYGCTL_ERROR;
    }

    return CYGCTL_OK;
}
