# hping3 Cygwin 移植文档

*hping3 3.0.0-alpha — Cygwin/Npcap/WinDivert 移植记录*

---

## 背景

hping3 原生只支持 Linux/BSD/Solaris。在 Cygwin 上有两个核心障碍：

1. **原始套接字注入**：Windows 不允许用户态 `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` 发包，需要用 WinDivert 替代
2. **扫描引擎**：scan 模式用 `fork()` + `shmget/shmat` 共享内存传递 portinfo，Cygwin 的 `fork()` 有限制，改用 pthreads + heap 内存

---

## 补丁列表（共 4 个）

### 0001-cygwin-platform-compat.patch
影响文件：`getifname.c`、`libpcap_stuff.c`、`interface.c`、`script.c`（共 5 处修改）

**问题 1：`net/bpf.h` 不存在**
- `libpcap_stuff.c` 和 `script.c` 都 `#include <net/bpf.h>`（BSD 专用头文件）
- Cygwin 用 `#include <pcap-bpf.h>` 替代

```c
/* 修复方式 */
#ifdef __CYGWIN__
#include <pcap-bpf.h>
#else
#include <net/bpf.h>
#endif
```

**问题 2：`BIOCIMMEDIATE` 未定义**
- `libpcap_stuff.c` 和 `script.c` 中的 `ioctl(... BIOCIMMEDIATE ...)` 是 BSD BPF 专用
- 在 `#if (!defined OSTYPE_LINUX) && (!defined __sun__)` 基础上加 `&& (!defined __CYGWIN__)`

**问题 3：平台检测 `#error`**
- `getifname.c` 和 `interface.c` 都有平台白名单，不含 Cygwin 会触发 `#error`
- 在两处均加 `&& !defined(__CYGWIN__)`

**问题 4：`hping_get_interfaces` 未实现**
- `interface.c` 的 Linux 实现 `#if (defined OSTYPE_LINUX) || (defined __sun__)` 不含 Cygwin
- Cygwin 支持相同的 `SIOCGIFCONF/SIOCGIFFLAGS/SIOCGIFADDR` 等 ioctl，可复用 Linux 实现
- `SIOCGIFINDEX` Cygwin 不支持，与 Solaris 一样设为 -1

```c
/* interface.c 两处修改 */

/* 1. 扩展实现分支 */
#if (defined OSTYPE_LINUX) || (defined __sun__) || (defined __CYGWIN__)

/* 2. SIOCGIFINDEX 跳过 */
#if defined(__sun__) || defined(__CYGWIN__)
    ifindex = -1;
#else
    if (ioctl(fd, SIOCGIFINDEX, (char*)&ifr) == -1) { ... }
    ifindex = ifr.ifr_ifindex;
#endif
```

**问题 5：pcap 接口名格式不兼容**
- Cygwin 的 `SIOCGIFCONF` 返回裸 GUID 格式（如 `{45CC73DE-B277-477B-A16B-4899F791CA26}`）
- Npcap 的 `pcap_open_live` 需要 `\Device\NPF_{GUID}` 格式，直接传 GUID 会失败

**Loopback 特殊情况**：Cygwin 的 `SIOCGIFCONF` 对 loopback 适配器同样返回一个 GUID
（如 `{0BDB47D8-E19C-11EB-82F5-806E6F6E6963}`），而 Npcap 将 loopback 暴露为
`\Device\NPF_Loopback` 而非普通的 NPF_{GUID} 设备。因此不能简单地用 GUID 拼接，
需要通过 `ifstraddr`（已由 `SIOCGIFADDR` 填好）判断是否为 127.x.x.x 来决定映射目标。

```c
/* libpcap_stuff.c open_pcap() */
#ifdef __CYGWIN__
    char npf_ifname[1040];
    const char *pcap_dev = ifname;
    if (ifname[0] == '{') {
        if (strncmp(ifstraddr, "127.", 4) == 0)
            /* loopback adapter: Npcap 特殊设备名 */
            snprintf(npf_ifname, sizeof(npf_ifname), "\\Device\\NPF_Loopback");
        else
            snprintf(npf_ifname, sizeof(npf_ifname), "\\Device\\NPF_%s", ifname);
        pcap_dev = npf_ifname;
    }
    pcapfp = pcap_open_live(pcap_dev, 99999, 0, 1, errbuf);
#else
    pcapfp = pcap_open_live(ifname, 99999, 0, 1, errbuf);
#endif
```

`script.c` 的 `HpingRecvGetHandler()` 也有独立的 `pcap_open_live(ifname, ...)` 调用（TCL 脚本模式使用），
同样加入了相同的 NPF 翻译块。`ifstraddr` 在 `script.c` 中不可见，用 `extern char ifstraddr[]`
局部声明引入，不引入额外 include。

---

### 0002-cygwin-scan-fork-to-pthread.patch
影响文件：`scan.c`

**问题：fork + shmget 扫描引擎**
- 原实现：`fork()` 产生子进程，父子通过 `shmget/shmat` 共享 `portinfo[65537]`
- Cygwin 的 `fork()` 性能差，SysV 共享内存有限制
- 改为：`calloc()` 分配 heap 上的 portinfo，`pthread_create()` 启动 sender/receiver 两个线程共享同一指针

**为什么 Cygwin fork 有问题**

Cygwin 的 `fork()` 必须在 Windows 上模拟 POSIX 语义：先 `CreateProcess` 创建子进程，
再把父进程的堆、栈、mmap 区域逐块复制过去，同时还要重新初始化所有已加载 DLL 的状态。
整个过程极慢（比 Linux 慢 10–100 倍），且在父进程加载了大量 DLL（如 tcl、wpcap）时容易因
地址空间布局不一致而崩溃（`fork: retry: Resource temporarily unavailable`）。

scan 模式的 `fork()` + `shmget` 方案在 Linux 上没问题，但在 Cygwin 上既慢又不稳定。
由于 sender 和 receiver 只需要共享同一块 `portinfo` 内存，完全不需要跨进程——改为
`pthread_create()` 在同一进程内起两个线程，直接共享 heap 指针，彻底绕开 fork 和 SysV shm，
稳定性和速度都大幅提升。

关键改动：
```c
/* 去掉 */
#include <sys/shm.h>
#include <sys/sem.h>
/* 加上 */
#include <pthread.h>

/* portinfo 字段加 volatile */
struct portinfo {
    volatile int active;
    int retry;
    volatile time_t sentms;
};

/* 前向声明（解决线程 wrapper 与函数定义顺序问题） */
static void sender(struct portinfo *pi);
static void receiver(struct portinfo *pi, int childpid);

/* 线程 wrapper */
static void *sender_thread(void *arg)   { sender((struct portinfo *)arg);   return NULL; }
static void *receiver_thread(void *arg) { receiver((struct portinfo *)arg, 0); return NULL; }

/* scanmain() 改动 */
pi = calloc(MAXPORT+2, sizeof(*pi));   /* 替代 shm_init() */
pthread_create(&receiver_tid, NULL, receiver_thread, pi);
pthread_create(&sender_tid,   NULL, sender_thread,   pi);
pthread_join(receiver_tid, NULL);
pthread_cancel(sender_tid);
free(pi);
```

---

### 0003-cygwin-windivert-injection.patch
影响文件：`opensockraw.c`、`sendip.c`、`Makefile.in`
新增文件：`windivert_inject.h`、`windivert_inject.c`

**问题：raw socket 在 Windows 被禁**
- Windows 拒绝用户态 `SOCK_RAW + IPPROTO_RAW`，即使是 administrator 也不可靠
- 解决：动态加载 WinDivert.dll，用 `WinDivertSend()` 注入出站 IP 包

**设计：sentinel 值 SOCKRAW_WINDIVERT_DUMMY (-2)**
- `open_sockraw()` 成功加载 WinDivert 时返回 -2 而非真实 fd
- `send_ip()` 检查 `sockraw == -2` 时走 WinDivert 路径

```c
/* opensockraw.c */
#ifdef __CYGWIN__
    if (windivert_inject_available())
        return SOCKRAW_WINDIVERT_DUMMY;   /* -2 */
#endif
    return socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

/* send_ip() */
#ifdef __CYGWIN__
    if (sockraw == SOCKRAW_WINDIVERT_DUMMY) {
        result = windivert_inject_send(packet, packetsize);
    } else {
#endif
        result = sendto(sockraw, packet, packetsize, 0, ...);
#ifdef __CYGWIN__
    }
#endif
```

**windivert_inject.c 关键实现：动态加载模式**

不在编译期链接 `WinDivert.lib`，而是运行时按需加载：

```c
static HMODULE  g_hWinDivert = NULL;
static WinDivertOpenFn    p_WinDivertOpen    = NULL;
static WinDivertSendFn    p_WinDivertSend    = NULL;
static WinDivertCloseFn   p_WinDivertClose   = NULL;

int windivert_inject_available(void) {
    if (g_hWinDivert) return 1;
    g_hWinDivert = LoadLibraryA("WinDivert.dll");
    if (!g_hWinDivert) return 0;
    p_WinDivertOpen  = (WinDivertOpenFn)  GetProcAddress(g_hWinDivert, "WinDivertOpen");
    p_WinDivertSend  = (WinDivertSendFn)  GetProcAddress(g_hWinDivert, "WinDivertSend");
    p_WinDivertClose = (WinDivertCloseFn) GetProcAddress(g_hWinDivert, "WinDivertClose");
    return (p_WinDivertOpen && p_WinDivertSend && p_WinDivertClose);
}
```

这样做的好处：
- 编译期不依赖 WinDivert SDK，Cygwin 包只需要头文件中的类型定义
- `windivert_inject_available()` 失败（WinDivert 未安装）时 `open_sockraw()` 直接走原始
  `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` 路径，程序仍可编译运行
- 与 CyXV-D3D 通过 `dlsym` / `GetProcAddress` 定位 XWin.exe 内部函数是同一设计模式

`WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_INJECT)`：
- 过滤器 `"false"` = 不捕获任何入站包，句柄仅用于发包
- `WINDIVERT_FLAG_INJECT` = 纯注入模式，跳过内核捕获队列，开销最小

---

### 0004-cygwin-configure-ostype.patch
影响文件：`configure`

**问题：`uname -s` 在 Cygwin 返回 `CYGWIN_NT-10.0-19045`**
- configure 把它直接写成 `#define OSTYPE_CYGWIN_NT-10.0-19045`
- `-` 和 `.` 是非法 C 宏名字符，导致所有 `.c` 文件编译时警告甚至错误

```sh
# 在 BSDI 规范化之后加入：
case $CONFIGOSTYPE in
  CYGWIN*) CONFIGOSTYPE=CYGWIN ;;
esac
```

生成正确的 `systype.h`：
```c
#define OSTYPE_CYGWIN   /* 合法 C 标识符 */
```

---

## Makefile 构建参数

configure 生成的 Makefile 默认 `PCAP=-lpcap`，Cygwin 需要用 Npcap 的导入库：

```makefile
COMPILE_TIME = -I/opt/cygwin-port/include -fcommon
PCAP         = -L/opt/cygwin-port/lib -lwpcap
```

`-fcommon`：hping2.h 中 `delaytable` 在头文件里直接定义变量（无 `extern`），GCC 10+ 默认 `-fno-common` 会报重复定义错误。

TCL 库：Cygwin 上是 `libtcl8.6.dll.a`，configure 探测 `tclsh` 版本后自动设置，无需手动指定。

---

## 运行时依赖

| 依赖 | 路径 | 用途 |
|------|------|------|
| `wpcap.dll` | `C:\Windows\System32\Npcap\` | pcap 抓包（Npcap 安装后自动在此） |
| `WinDivert.dll` | 系统 PATH 或程序目录 | 原始包注入 |
| `WinDivert.sys` | `C:\Windows\System32\drivers\` | WinDivert 内核驱动 |

**运行需要管理员权限**（WinDivert 和 raw socket 均需要）：
```bash
sudo hping3 -1 -c 3 192.168.1.1
```

`wpcap.dll` 位于 `C:\Windows\System32\Npcap\`，不在默认 DLL 搜索路径中。
cygctl 的 `sudo` 会在提权时自动将该目录注入到 PATH 最前，无需手动设置。

> **注意：WinPcap 残留冲突**
> 若系统中残留旧版 WinPcap（`wpcap.dll` 在 `C:\Windows\System32\`），DLL 加载器会优先找到它，
> 导致 `pcap_open_live` 失败（错误 126：找不到指定的模块）。
> 解决方法：重装 Npcap 时勾选 "Install Npcap in WinPcap API-compatible Mode"，
> 覆盖 System32 中的旧 DLL。

---

## cygport 自动化

补丁已收录于 `D:\cygport\patches\hping3\`，通过 `port.sh` 全自动构建：

```bash
cd /cygdrive/d/cygport
bash port.sh hping3            # download + apply + build + install
bash port.sh hping3 --apply    # 仅打补丁
bash port.sh hping3 --build    # 仅编译
```

`pkg.conf` 关键配置：
```bash
PKG_URL="https://github.com/antirez/hping/archive/refs/heads/master.tar.gz"
BUILD_TYPE="configure_make"
MAKE_ARGS=(
    "COMPILE_TIME=-I/opt/cygwin-port/include -fcommon"
    "PCAP=-L/opt/cygwin-port/lib -lwpcap"
)
```

---

## 验证结果

全流程通过全新源码（fresh source）测试：

```
[+] Applying 0001-cygwin-platform-compat.patch   — 4 files, clean
[+] Applying 0002-cygwin-scan-fork-to-pthread.patch — 1 file, clean
[+] Applying 0003-cygwin-windivert-injection.patch  — 5 files, clean
[+] Applying 0004-cygwin-configure-ostype.patch     — 1 file, clean
hping version 3.0.0-alpha-1 (...)
[port] installed hping3.exe -> /usr/local/bin/
```

功能验证：

| 目标 | 结果 |
|------|------|
| `sudo hping3 -1 -c 3 8.8.8.8` | 3/3 packets, 0% loss, rtt ~16ms ✅ |
| `sudo hping3 -1 -c 3 127.0.0.1` | loopback via `\Device\NPF_Loopback` ✅ |
| TCL 模式 `hping recv {GUID} 2000 1` | `pcap_open_live` 成功（NPF 翻译在 script.c 路径生效）✅ |

---

## 已知限制

- TCL 脚本支持已实现，但未做完整覆盖测试
- `hping_get_interfaces` 的 `hif_index` 字段在 Cygwin 上始终为 -1（不影响基本功能）
- scan 模式的 pthread 实现去掉了原来的 `SIGCHLD` 信号处理（pthread 不需要）
