/**
 * @file cygctl_route.c
 * @brief cygctl1.dll - 路由操作实现
 */

#include "cygctl_internal.h"

/* ========== 获取默认网关 ========== */

int cygctl_route_get_default(char* out_gateway, char* out_interface) {
    if (!out_gateway) {
        return CYGCTL_INVALID_ARG;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 使用 GetIpForwardTable 获取路由表 */
    PMIB_IPFORWARDTABLE route_table = NULL;
    ULONG buf_len = 0;

    /* 获取需要的缓冲区大小 */
    if (GetIpForwardTable(NULL, &buf_len, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        cygctl_set_error("GetIpForwardTable size query failed");
        return CYGCTL_ERROR;
    }

    route_table = malloc(buf_len);
    if (!route_table) {
        return CYGCTL_NO_MEMORY;
    }

    if (GetIpForwardTable(route_table, &buf_len, FALSE) != NO_ERROR) {
        free(route_table);
        cygctl_set_error("GetIpForwardTable failed");
        return CYGCTL_ERROR;
    }

    /* 查找默认路由 (0.0.0.0/0) */
    DWORD default_gateway = 0;
    DWORD default_index = 0;
    DWORD min_metric = 0xFFFFFFFF;

    for (DWORD i = 0; i < route_table->dwNumEntries; i++) {
        MIB_IPFORWARDROW* row = &route_table->table[i];

        /* 默认路由：目的地为 0.0.0.0，掩码为 0.0.0.0 */
        if (row->dwForwardDest == 0 && row->dwForwardMask == 0) {
            /* 选择跃点数最低的 */
            DWORD metric = row->dwForwardMetric1;
            if (metric < min_metric) {
                min_metric = metric;
                default_gateway = row->dwForwardNextHop;
                default_index = row->dwForwardIfIndex;
            }
        }
    }

    free(route_table);

    if (default_gateway == 0) {
        cygctl_set_error("No default gateway found");
        return CYGCTL_ERROR;
    }

    /* 输出网关 IP（使用 inet_ntop 避免 inet_ntoa 的非线程安全问题） */
    struct in_addr addr;
    addr.s_addr = default_gateway;
    inet_ntop(AF_INET, &addr, out_gateway, 47);
    out_gateway[47] = '\0';

    /* 获取接口名称（可选） */
    if (out_interface) {
        out_interface[0] = '\0';  /* 修复：避免未初始化读取 */
        /* 通过接口索引获取接口信息 */
        PMIB_IPADDRTABLE addr_table = NULL;
        ULONG addr_buf_len = 0;

        if (GetIpAddrTable(NULL, &addr_buf_len, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
            addr_table = malloc(addr_buf_len);
            if (addr_table && GetIpAddrTable(addr_table, &addr_buf_len, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < addr_table->dwNumEntries; i++) {
                    if (addr_table->table[i].dwIndex == default_index) {
                        snprintf(out_interface, 64, "eth%lu",
                                 addr_table->table[i].dwIndex);
                        break;
                    }
                }
            }
            free(addr_table);
        }

        if (out_interface[0] == '\0') {
            strcpy(out_interface, "unknown");
        }
    }

    return CYGCTL_OK;
}

/* ========== 添加路由 ========== */

int cygctl_route_add(const char* dest, const char* gateway, int metric) {
    if (!dest || !gateway) {
        return CYGCTL_INVALID_ARG;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 解析目标网络 (格式: IP/MASK 或 IP) */
    char dest_ip[48] = {0};
    char dest_mask[48] = "255.255.255.255";
    char* slash = strchr((char*)dest, '/');

    if (slash) {
        size_t ip_len = slash - dest;
        if (ip_len >= sizeof(dest_ip)) {
            ip_len = sizeof(dest_ip) - 1;
        }
        strncpy(dest_ip, dest, ip_len);

        /* 解析掩码（CIDR 或点分十进制） */
        char* mask_str = slash + 1;
        int cidr = atoi(mask_str);
        if (cidr > 0 && cidr <= 32) {
            /* CIDR 格式，转换为点分十进制 */
            uint32_t mask = cidr == 32 ? 0xFFFFFFFF : htonl(0xFFFFFFFF << (32 - cidr));
            struct in_addr mask_addr;
            mask_addr.s_addr = mask;
            strncpy(dest_mask, inet_ntoa(mask_addr), sizeof(dest_mask) - 1);
        } else {
            /* 点分十进制格式 */
            strncpy(dest_mask, mask_str, sizeof(dest_mask) - 1);
        }
    } else {
        strncpy(dest_ip, dest, sizeof(dest_ip) - 1);
    }

    /* 解析网关 */
    struct in_addr gateway_addr;
    if (inet_pton(AF_INET, gateway, &gateway_addr) != 1) {
        cygctl_set_error("Invalid gateway IP: %s", gateway);
        return CYGCTL_INVALID_ARG;
    }

    /* 查找最佳接口 */
    DWORD best_if_index = 0;
    if (GetBestInterface(gateway_addr.s_addr, &best_if_index) != NO_ERROR) {
        cygctl_set_error("GetBestInterface failed for gateway %s", gateway);
        return CYGCTL_ERROR;
    }

    /* 构建路由条目 */
    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));

    struct in_addr dest_addr, mask_addr;
    inet_pton(AF_INET, dest_ip, &dest_addr);
    inet_pton(AF_INET, dest_mask, &mask_addr);

    row.dwForwardDest = dest_addr.s_addr;
    row.dwForwardMask = mask_addr.s_addr;
    row.dwForwardPolicy = 0;
    row.dwForwardNextHop = gateway_addr.s_addr;
    row.dwForwardIfIndex = best_if_index;
    row.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;  /* 下一跳路由 */
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;       /* 手动配置 */
    row.dwForwardAge = 0;
    row.dwForwardNextHopAS = 0;
    row.dwForwardMetric1 = metric > 0 ? metric : 1;
    row.dwForwardMetric2 = 0;
    row.dwForwardMetric3 = 0;
    row.dwForwardMetric4 = 0;
    row.dwForwardMetric5 = 0;

    DWORD ret = CreateIpForwardEntry(&row);
    if (ret != NO_ERROR) {
        cygctl_set_error("CreateIpForwardEntry failed: %lu (requires admin?)", ret);
        return CYGCTL_ERROR;
    }

    return CYGCTL_OK;
}

/* ========== 删除路由 ========== */

int cygctl_route_del(const char* dest) {
    if (!dest) {
        return CYGCTL_INVALID_ARG;
    }

    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return CYGCTL_NOT_INITIALIZED;
    }

    /* 解析目标网络 */
    char dest_ip[48] = {0};
    char dest_mask[48] = "255.255.255.255";
    char* slash = strchr((char*)dest, '/');

    if (slash) {
        size_t ip_len = slash - dest;
        if (ip_len >= sizeof(dest_ip)) {
            ip_len = sizeof(dest_ip) - 1;
        }
        strncpy(dest_ip, dest, ip_len);

        char* mask_str = slash + 1;
        int cidr = atoi(mask_str);
        if (cidr > 0 && cidr <= 32) {
            uint32_t mask = cidr == 32 ? 0xFFFFFFFF : htonl(0xFFFFFFFF << (32 - cidr));
            struct in_addr mask_addr;
            mask_addr.s_addr = mask;
            strncpy(dest_mask, inet_ntoa(mask_addr), sizeof(dest_mask) - 1);
        } else {
            strncpy(dest_mask, mask_str, sizeof(dest_mask) - 1);
        }
    } else {
        strncpy(dest_ip, dest, sizeof(dest_ip) - 1);
    }

    /* 查找现有路由 */
    PMIB_IPFORWARDTABLE route_table = NULL;
    ULONG buf_len = 0;

    if (GetIpForwardTable(NULL, &buf_len, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        cygctl_set_error("GetIpForwardTable size query failed");
        return CYGCTL_ERROR;
    }

    route_table = malloc(buf_len);
    if (!route_table) {
        return CYGCTL_NO_MEMORY;
    }

    if (GetIpForwardTable(route_table, &buf_len, FALSE) != NO_ERROR) {
        free(route_table);
        cygctl_set_error("GetIpForwardTable failed");
        return CYGCTL_ERROR;
    }

    /* 查找匹配的路由 */
    struct in_addr target_dest, target_mask;
    inet_pton(AF_INET, dest_ip, &target_dest);
    inet_pton(AF_INET, dest_mask, &target_mask);

    int found = 0;
    for (DWORD i = 0; i < route_table->dwNumEntries; i++) {
        MIB_IPFORWARDROW* row = &route_table->table[i];

        if (row->dwForwardDest == target_dest.s_addr &&
            row->dwForwardMask == target_mask.s_addr) {

            /* 删除路由 */
            DWORD ret = DeleteIpForwardEntry(row);
            if (ret != NO_ERROR) {
                free(route_table);
                cygctl_set_error("DeleteIpForwardEntry failed: %lu", ret);
                return CYGCTL_ERROR;
            }
            found = 1;
            break;
        }
    }

    free(route_table);

    if (!found) {
        cygctl_set_error("Route %s not found", dest);
        return CYGCTL_ERROR;
    }

    return CYGCTL_OK;
}
