/**
 * @file cygctl.h
 * @brief cygctl1.dll - KaliNT 底层抽象层
 *
 * 纯净的对外接口，只使用 C 标准类型。
 * 所有 Win32 类型被封装在不透明指针中。
 *
 * 设计原则：
 * - 禁止出现 HANDLE, SOCKET, DWORD 等 Win32 类型
 * - 所有复杂对象使用 void* 不透明指针
 * - 零 POSIX 依赖，可被任何 Windows 程序调用
 *
 * @version 1.0
 * @date 2026-03-13
 */

#ifndef CYGCTL_API_H
#define CYGCTL_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========== IPv6 兼容性宏 (Cygwin 缺失定义) ========== */
#ifndef WIN32
#ifndef IPV6_DSTOPTS
#define IPV6_DSTOPTS 0
#endif
#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS 0
#endif
#ifndef IPV6_RTHDR
#define IPV6_RTHDR 0
#endif
#ifndef IPV6_TCLASS
#define IPV6_TCLASS 0
#endif
#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 0
#endif
#endif

/* ========== 版本信息 ========== */
#define CYGCTL_VERSION_MAJOR 1
#define CYGCTL_VERSION_MINOR 0
#define CYGCTL_VERSION_STRING "1.0.0"

/* ========== 不透明句柄类型 ========== */
/** 通用句柄（底层可能是 HANDLE） */
typedef void* cygctl_handle_t;

/** 套接字句柄（底层可能是 SOCKET） */
typedef void* cygctl_socket_t;

/** PCAP 句柄 */
typedef void* cygctl_pcap_t;

/** 扫描器句柄 */
typedef void* cygctl_scanner_t;

/* ========== 错误码 ========== */
#define CYGCTL_OK               0    /**< 成功 */
#define CYGCTL_ERROR           -1    /**< 通用错误 */
#define CYGCTL_TIMEOUT         -2    /**< 操作超时 */
#define CYGCTL_INVALID_HANDLE  -3    /**< 无效句柄 */
#define CYGCTL_WOULD_BLOCK     -4    /**< 非阻塞操作会阻塞 */
#define CYGCTL_NO_MEMORY       -5    /**< 内存不足 */
#define CYGCTL_INVALID_ARG     -6    /**< 无效参数 */
#define CYGCTL_NOT_SUPPORTED   -7    /**< 不支持的操作 */
#define CYGCTL_NOT_INITIALIZED -8    /**< 未初始化 */

/* ========== 初始化/清理 ========== */

/**
 * @brief 初始化网络子系统
 * @return CYGCTL_OK 成功，其他值失败
 *
 * 必须在使用任何其他 API 之前调用。
 * 内部会调用 WSAStartup() 并获取 ConnectEx 函数指针。
 */
int cygctl_init(void);

/**
 * @brief 清理网络子系统
 *
 * 程序退出前调用，内部会调用 WSACleanup()。
 */
void cygctl_cleanup(void);

/**
 * @brief 获取错误描述字符串
 * @param error_code 错误码
 * @return 错误描述字符串（静态存储，不需要释放）
 */
const char* cygctl_strerror(int error_code);

/**
 * @brief 获取最后一次错误的详细信息
 * @return 错误描述字符串（静态存储，不需要释放）
 */
const char* cygctl_last_error(void);

/* ========== 网络接口 API ========== */

/**
 * @brief 网络接口信息
 */
typedef struct cygctl_interface {
    char name[64];          /**< 接口名称 (e.g., "eth0") */
    char pcap_name[256];    /**< PCAP 设备名 (e.g., "\Device\NPF_{GUID}") */
    char ip[48];            /**< IPv4 地址 */
    char netmask[48];       /**< 子网掩码 */
    char mac[18];           /**< MAC 地址 (e.g., "00:11:22:33:44:55") */
    int mtu;                /**< MTU */
    int is_up;              /**< 是否启用 */
    int is_loopback;        /**< 是否为回环接口 */
} cygctl_interface_t;

/**
 * @brief 获取所有网络接口
 * @param interfaces 输出接口数组（需要调用者释放）
 * @param count 输出接口数量
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_get_interfaces(cygctl_interface_t** interfaces, int* count);

/**
 * @brief 释放接口数组
 * @param interfaces 接口数组
 */
void cygctl_free_interfaces(cygctl_interface_t* interfaces);

/**
 * @brief 将 dnet 设备名转换为 pcap 设备名
 * @param dnet_name dnet 设备名 (e.g., "eth0")
 * @param pcap_name 输出缓冲区
 * @param pcap_name_len 缓冲区长度
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_dnet_to_pcap(const char* dnet_name, char* pcap_name, int pcap_name_len);

/* ========== 高性能扫描器 API (IOCP) ========== */

/**
 * @brief 扫描结果
 */
typedef struct cygctl_scan_result {
    char ip[48];            /**< 目标 IP */
    uint16_t port;          /**< 目标端口 */
    int status;             /**< 0=超时, 1=开放, -1=错误 */
    int error_code;         /**< 详细错误码 */
    uint32_t latency_ms;    /**< 延迟（毫秒） */
} cygctl_scan_result_t;

/**
 * @brief 创建高性能扫描器
 * @param max_concurrent 最大并发连接数
 * @return 扫描器句柄，失败返回 NULL
 */
cygctl_scanner_t cygctl_scanner_create(int max_concurrent);

/**
 * @brief 销毁扫描器
 * @param scanner 扫描器句柄
 */
void cygctl_scanner_destroy(cygctl_scanner_t scanner);

/**
 * @brief 发起异步连接
 * @param scanner 扫描器句柄
 * @param ip 目标 IP
 * @param port 目标端口
 * @param timeout_ms 超时时间（毫秒）
 * @return CYGCTL_OK 成功加入队列，其他值失败
 */
int cygctl_scan_fire(cygctl_scanner_t scanner,
                      const char* ip,
                      uint16_t port,
                      int timeout_ms);

/**
 * @brief 批量获取扫描结果
 * @param scanner 扫描器句柄
 * @param results 输出结果数组
 * @param max_count 最大结果数
 * @param timeout_ms 等待超时（毫秒），0 表示立即返回
 * @return 获取到的结果数，失败返回负数
 */
int cygctl_scan_poll(cygctl_scanner_t scanner,
                      cygctl_scan_result_t* results,
                      int max_count,
                      int timeout_ms);

/**
 * @brief 获取扫描器统计信息
 * @param scanner 扫描器句柄
 * @param pending 输出待处理数量
 * @param completed 输出已完成数量
 */
void cygctl_scanner_stats(cygctl_scanner_t scanner,
                           int* pending,
                           int* completed);

/* ========== 原始套接字 API ========== */

/**
 * @brief 协议类型
 */
#define CYGCTL_PROTO_ICMP  1
#define CYGCTL_PROTO_TCP   6
#define CYGCTL_PROTO_UDP  17

/**
 * @brief 创建原始套接字
 * @param protocol 协议类型 (CYGCTL_PROTO_*)
 * @return 套接字句柄，失败返回 NULL
 *
 * 注意：需要管理员权限
 */
cygctl_socket_t cygctl_raw_socket(int protocol);

/**
 * @brief 发送原始数据
 * @param sock 套接字句柄
 * @param data 数据缓冲区
 * @param len 数据长度
 * @param dest_ip 目标 IP
 * @return 发送的字节数，失败返回负数
 */
int cygctl_raw_send(cygctl_socket_t sock,
                     const void* data,
                     size_t len,
                     const char* dest_ip);

/**
 * @brief 接收原始数据
 * @param sock 套接字句柄
 * @param buffer 接收缓冲区
 * @param max_len 缓冲区大小
 * @param src_ip 输出源 IP（可为 NULL）
 * @param timeout_ms 超时时间（毫秒）
 * @return 接收的字节数，超时返回 0，失败返回负数
 */
int cygctl_raw_recv(cygctl_socket_t sock,
                     void* buffer,
                     size_t max_len,
                     char* src_ip,
                     int timeout_ms);

/**
 * @brief 关闭原始套接字
 * @param sock 套接字句柄
 */
void cygctl_raw_close(cygctl_socket_t sock);

/* ========== ARP 操作 ========== */

/**
 * @brief 获取 ARP 表中的 MAC 地址
 * @param ip 目标 IP
 * @param out_mac 输出 MAC 地址缓冲区（至少 18 字节）
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_arp_get(const char* ip, char* out_mac);

/**
 * @brief 设置 ARP 表项
 * @param ip 目标 IP
 * @param mac MAC 地址字符串 (e.g., "00:11:22:33:44:55")
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_arp_set(const char* ip, const char* mac);

/* ========== 路由操作 ========== */

/**
 * @brief 获取默认网关
 * @param out_gateway 输出网关 IP（至少 48 字节）
 * @param out_interface 输出接口名（至少 64 字节，可为 NULL）
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_route_get_default(char* out_gateway, char* out_interface);

/**
 * @brief 添加路由
 * @param dest 目标网络 (e.g., "192.168.1.0/24")
 * @param gateway 网关 IP
 * @param metric 跃点数
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_route_add(const char* dest, const char* gateway, int metric);

/**
 * @brief 删除路由
 * @param dest 目标网络
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_route_del(const char* dest);

/* ========== PCAP 数据包捕获 API ========== */

/**
 * @brief 数据包回调函数类型
 * @param data 数据包内容
 * @param len 数据包长度
 * @param src_ip 源 IP（可为 NULL）
 * @param user_data 用户数据
 */
typedef void (*cygctl_pcap_callback_t)(const void* data, size_t len,
                                        const char* src_ip, void* user_data);

/**
 * @brief 打开 PCAP 设备
 * @param device 设备名（pcap 格式，如 "\Device\NPF_{GUID}"）
 * @param snaplen 捕获长度
 * @param promisc 混杂模式（非零启用）
 * @param timeout_ms 超时时间（毫秒）
 * @return PCAP 句柄，失败返回 NULL
 */
cygctl_pcap_t cygctl_pcap_open(const char* device, int snaplen, int promisc, int timeout_ms);

/**
 * @brief 设置 BPF 过滤器
 * @param pcap PCAP 句柄
 * @param filter BPF 过滤表达式
 * @return CYGCTL_OK 成功，其他值失败
 */
int cygctl_pcap_set_filter(cygctl_pcap_t pcap, const char* filter);

/**
 * @brief 捕获数据包
 * @param pcap PCAP 句柄
 * @param max_packets 最大数据包数
 * @param callback 回调函数
 * @param user_data 用户数据
 * @return 捕获的数据包数，失败返回负数
 */
int cygctl_pcap_dispatch(cygctl_pcap_t pcap, int max_packets,
                          cygctl_pcap_callback_t callback, void* user_data);

/**
 * @brief 获取下一个数据包（阻塞）
 * @param pcap PCAP 句柄
 * @param buffer 输出缓冲区
 * @param max_len 缓冲区大小
 * @return 数据包长度，超时返回 0，失败返回负数
 */
int cygctl_pcap_next(cygctl_pcap_t pcap, void* buffer, size_t max_len);

/**
 * @brief 关闭 PCAP 设备
 * @param pcap PCAP 句柄
 */
void cygctl_pcap_close(cygctl_pcap_t pcap);

/**
 * @brief 获取 PCAP 错误信息
 * @param pcap PCAP 句柄
 * @return 错误字符串
 */
const char* cygctl_pcap_geterr(cygctl_pcap_t pcap);

#ifdef __cplusplus
}
#endif

#endif /* CYGCTL_API_H */
