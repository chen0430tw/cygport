/**
 * @file cygctl_iocp.c
 * @brief cygctl1.dll - IOCP 高性能扫描器实现
 *
 * 使用 Windows IOCP (I/O Completion Ports) 实现异步端口扫描。
 * 这是 nmap -sT (TCP connect scan) 的高性能版本。
 */

#include "cygctl_internal.h"

/* ========== 扫描器创建/销毁 ========== */

cygctl_scanner_t cygctl_scanner_create(int max_concurrent) {
    if (!g_initialized) {
        cygctl_set_error("Library not initialized");
        return NULL;
    }

    struct cygctl_scanner* s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }

    /* 创建 IOCP */
    s->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (s->iocp == NULL) {
        cygctl_set_error("CreateIoCompletionPort failed: %lu", GetLastError());
        free(s);
        return NULL;
    }

    /* 初始化线程锁 */
    InitializeCriticalSection(&s->lock);

    s->max_concurrent = max_concurrent;
    s->active_count = 0;
    s->total_fired = 0;
    s->total_completed = 0;
    s->req_head = NULL;

    return s;
}

void cygctl_scanner_destroy(cygctl_scanner_t scanner) {
    if (!scanner) {
        return;
    }

    struct cygctl_scanner* s = (struct cygctl_scanner*)scanner;

    /* 关闭所有待处理请求的套接字并释放内存
     * 原实现直接 CloseHandle(iocp) 会泄漏 req 结构体 */
    EnterCriticalSection(&s->lock);
    struct cygctl_scan_request* req = s->req_head;
    while (req) {
        struct cygctl_scan_request* next = req->next;
        closesocket(req->socket);
        free(req);
        req = next;
    }
    s->req_head = NULL;
    s->active_count = 0;
    LeaveCriticalSection(&s->lock);

    if (s->iocp) {
        CloseHandle(s->iocp);
    }

    DeleteCriticalSection(&s->lock);
    free(s);
}

/* ========== 异步连接 ========== */

int cygctl_scan_fire(cygctl_scanner_t scanner,
                      const char* ip,
                      uint16_t port,
                      int timeout_ms) {
    if (!scanner) {
        return CYGCTL_INVALID_HANDLE;
    }

    if (!ip || port == 0) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_scanner* s = (struct cygctl_scanner*)scanner;

    EnterCriticalSection(&s->lock);

    /* 检查并发限制 */
    if (s->active_count >= s->max_concurrent) {
        LeaveCriticalSection(&s->lock);
        cygctl_set_error("Max concurrent connections reached (%d)", s->max_concurrent);
        return CYGCTL_WOULD_BLOCK;
    }

    /* 创建套接字 */
    SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                            NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        LeaveCriticalSection(&s->lock);
        cygctl_set_error("WSASocket failed: %d", WSAGetLastError());
        return CYGCTL_ERROR;
    }

    /* 绑定到任意端口 */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = 0;

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        closesocket(sock);
        LeaveCriticalSection(&s->lock);
        cygctl_set_error("bind failed: %d", WSAGetLastError());
        return CYGCTL_ERROR;
    }

    /* 关联到 IOCP */
    if (CreateIoCompletionPort((HANDLE)sock, s->iocp, (ULONG_PTR)sock, 0) == NULL) {
        closesocket(sock);
        LeaveCriticalSection(&s->lock);
        cygctl_set_error("CreateIoCompletionPort failed: %lu", GetLastError());
        return CYGCTL_ERROR;
    }

    /* 目标地址 */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dest.sin_addr) != 1) {
        closesocket(sock);
        LeaveCriticalSection(&s->lock);
        cygctl_set_error("Invalid IP address: %s", ip);
        return CYGCTL_INVALID_ARG;
    }

    /* 分配请求结构 */
    struct cygctl_scan_request* req = calloc(1, sizeof(*req));
    if (!req) {
        closesocket(sock);
        LeaveCriticalSection(&s->lock);
        return CYGCTL_NO_MEMORY;
    }

    req->socket = sock;
    req->port = port;
    req->timeout_ms = timeout_ms > 0 ? timeout_ms : CYGCTL_SCAN_TIMEOUT_DEFAULT;
    req->start_time = GetTickCount();
    req->next = NULL;
    strncpy(req->ip, ip, sizeof(req->ip) - 1);

    /* 使用 ConnectEx 异步连接 */
    if (g_connectex) {
        DWORD bytes;
        BOOL result = g_connectex(sock, (struct sockaddr*)&dest, sizeof(dest),
                                   NULL, 0, &bytes, &req->overlapped);

        if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
            /* 立即失败，req 尚未入链表，直接释放 */
            closesocket(sock);
            free(req);
            LeaveCriticalSection(&s->lock);
            cygctl_set_error("ConnectEx failed: %d", WSAGetLastError());
            return CYGCTL_ERROR;
        }
    } else {
        /* 回退到非阻塞 connect */
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(sock);
                free(req);
                LeaveCriticalSection(&s->lock);
                cygctl_set_error("connect failed: %d", WSAGetLastError());
                return CYGCTL_ERROR;
            }
        }
    }

    /* ConnectEx 已挂起，现在才加入链表（避免 free 后还在链表里） */
    req->next = s->req_head;
    s->req_head = req;
    s->active_count++;
    s->total_fired++;

    LeaveCriticalSection(&s->lock);
    return CYGCTL_OK;
}

/* ========== 结果轮询 ========== */

int cygctl_scan_poll(cygctl_scanner_t scanner,
                      cygctl_scan_result_t* results,
                      int max_count,
                      int timeout_ms) {
    if (!scanner) {
        return CYGCTL_INVALID_HANDLE;
    }

    if (!results || max_count <= 0) {
        return CYGCTL_INVALID_ARG;
    }

    struct cygctl_scanner* s = (struct cygctl_scanner*)scanner;
    int completed = 0;
    DWORD start_time = GetTickCount();

    while (completed < max_count) {
        /* 检查超时 */
        if (timeout_ms > 0) {
            DWORD elapsed = GetTickCount() - start_time;
            if (elapsed >= (DWORD)timeout_ms) {
                break;
            }
        }

        /* 如果没有活跃连接，直接返回 */
        EnterCriticalSection(&s->lock);
        int active = s->active_count;
        LeaveCriticalSection(&s->lock);

        if (active == 0 && completed > 0) {
            break;
        }

        /* 从 IOCP 获取完成的操作 */
        DWORD bytes_transferred;
        ULONG_PTR completion_key;
        OVERLAPPED* overlapped = NULL;

        DWORD remaining = 100;  /* 每次最多等待 100ms */
        if (timeout_ms > 0) {
            DWORD elapsed = GetTickCount() - start_time;
            if (elapsed < (DWORD)timeout_ms) {
                remaining = (DWORD)timeout_ms - elapsed;
            }
        }

        BOOL success = GetQueuedCompletionStatus(
            s->iocp,
            &bytes_transferred,
            &completion_key,
            &overlapped,
            remaining
        );

        if (!overlapped) {
            /* 超时或没有完成的操作 */
            continue;
        }

        /* 获取请求结构 */
        struct cygctl_scan_request* req = CONTAINING_RECORD(overlapped,
                                                             struct cygctl_scan_request,
                                                             overlapped);

        /* 填充结果 */
        strncpy(results[completed].ip, req->ip, sizeof(results[completed].ip) - 1);
        results[completed].port = req->port;
        results[completed].latency_ms = GetTickCount() - req->start_time;

        if (success) {
            /* ConnectEx 完成，连接成功 */
            results[completed].status = 1;
            results[completed].error_code = 0;
        } else {
            /* 连接失败：优先用 overlapped->Internal（NTSTATUS），其次 GetLastError */
            DWORD error = (DWORD)GetLastError();
            if (overlapped->Internal != 0) {
                error = (DWORD)overlapped->Internal;
            }
            /* STATUS_TIMEOUT = 0xC0000000|0x102，也可能是 ERROR_SEM_TIMEOUT(121) */
            if (error == ERROR_SEM_TIMEOUT || error == WAIT_TIMEOUT ||
                error == ERROR_TIMEOUT   || error == 0xC0000102) {
                results[completed].status = 0;  /* 超时（端口过滤/无响应） */
            } else {
                results[completed].status = -1;  /* 拒绝或其他错误 */
            }
            results[completed].error_code = error;
        }

        /* 从链表移除（在 free 之前） */
        EnterCriticalSection(&s->lock);
        struct cygctl_scan_request** pp = &s->req_head;
        while (*pp && *pp != req) pp = &(*pp)->next;
        if (*pp) *pp = req->next;
        s->active_count--;
        s->total_completed++;
        LeaveCriticalSection(&s->lock);

        /* 清理 */
        closesocket(req->socket);
        free(req);

        completed++;
    }

    return completed;
}

/* ========== 统计信息 ========== */

void cygctl_scanner_stats(cygctl_scanner_t scanner,
                           int* pending,
                           int* completed) {
    if (!scanner) {
        if (pending) *pending = 0;
        if (completed) *completed = 0;
        return;
    }

    struct cygctl_scanner* s = (struct cygctl_scanner*)scanner;

    EnterCriticalSection(&s->lock);
    if (pending) *pending = s->active_count;
    if (completed) *completed = s->total_completed;
    LeaveCriticalSection(&s->lock);
}
