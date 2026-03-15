# cygport

Cygwin 网络工具移植运行时。提供在 Cygwin 环境下移植 Linux 网络工具（nmap、tcpdump 等）所需的底层库和头文件。

## 背景

2001 年，有人在 nmap 开发邮件列表问：「nmap 能用 Cygwin 的 gcc 编译吗？」

开发者的回答是：Unix 的 routing/pcap 算法在 Windows 上不工作。这条路就此搁置。

此后 20 年，社区里所谓的「nmap on Cygwin」方案，始终停留在：

```bash
alias nmap="C:/Program Files (x86)/Nmap/nmap.exe"
```

一个指向 Windows 原生二进制的 alias，从未有人真正移植过。nmap 官方文档至今写道：

> "Nmap doesn't maintain instructions for building Nmap under Cygwin."

WinDivert 出现后，内核级数据包拦截在用户态变得可行。Npcap 取代了老旧的 WinPcap。技术条件早已成熟，但没有人把这些拼在一起。

cygport 是这个空白的答案：一套让 Linux 网络工具在 Cygwin 上原生编译、原生运行的基础设施。不是 alias，不是 wrapper，是真正的移植。

### 移植一个工具，过去需要什么

在 cygport 存在之前，移植 nmap 的过程是这样的：

1. **逐文件手动打补丁** — `nsock_pcap.h`、`netutil.cc`、`intf.c`、`nbase_config.h`……每个文件单独找问题、单独改
2. **手工生成导入库** — 对着 `wpcap.dll`、`Packet.dll`、`cygctl1.dll` 各写一份 `.def`，再用 `dlltool` 生成 `.a`
3. **手写 pcap stub** — `pcap_get_selectable_fd()` Npcap 不支持，自己写个空实现
4. **手动调 Makefile** — `LIBS`、`CPPFLAGS` 逐项加，顺序还不能错
5. **必须用 Cygwin login shell 跑 configure** — 用 MSYS2 shell 会把路径写错，Makefile 全坏
6. **每次 configure 后重新修** — `nbase_config.h` 会被覆盖，`HAVE_ASNPRINTF` 得重新加

整个过程没有文档，靠的是一次次踩坑积累的经验。

### cygport 之后

| 问题 | 手工时代 | cygport |
|------|---------|---------|
| GNU 扩展 / IPv6 宏缺失 | 每个文件手改 | `-include cygctl_compat.h` 自动注入 |
| 接口名映射（eth0 ↔ NPF GUID） | cygctl1 内部重复实现 | `cygnet.dll` 统一提供 |
| Npcap 不存在时无法抓包 | 直接报错 | `cygnet.dll` 自动降级到 WinDivert |
| 导入库 | 每次手写 `.def` + `dlltool` | `-lcygnet -lcygctl1` 直接链接 |
| 移植下一个工具 | 从头踩一遍坑 | 框架已有，只补 tool-specific 补丁 |

cygport 把那份手工经验固化成了可复用的基础设施。

## 组件

| 组件 | 编译器 | 说明 |
|------|--------|------|
| `cygctl1.dll` | MinGW-w64 | 高层网络运行时：ARP、路由、原始套接字、IOCP 扫描器、pcap 封装 |
| `cygnet.dll` | Cygwin gcc | pcap 抽象层：接口名映射（eth0 ↔ NPF GUID）、Npcap 懒加载、WinDivert 后备 |
| `include/cygctl_compat.h` | 头文件 | 移植兼容层，编译时通过 `-include` 注入，处理 GNU 扩展、IPv6 缺失宏 |

## 架构

```
移植工具（nmap 等）
    │
    ├── cygctl_compat.h   编译期：GNU 扩展、WIN32_LEAN_AND_MEAN、IPv6 常量
    │
    ├── cygctl1.dll       运行期（高层）：raw socket、ARP、路由、IOCP 扫描器
    │
    └── cygnet.dll        运行期（pcap 层）：
                              ├── Npcap 后端（有安装时）
                              └── WinDivert 后端（无 Npcap 时自动降级）
```

## 编译

### 前置条件

- Cygwin（含 gcc、make）
- MinGW-w64（`x86_64-w64-mingw32-gcc`）
- Npcap SDK（放置于 `/opt/npcap/`）
- WinDivert SDK（可选，放置于 `/opt/WinDivert/`）

### 构建

```bash
make          # 构建全部
make cygctl1  # 仅构建 cygctl1.dll
make cygnet   # 仅构建 cygnet.dll
```

### 安装到 Cygwin

```bash
make install
```

安装位置：
- `/usr/bin/cygctl1.dll`
- `/usr/bin/cygnet.dll`
- `/usr/lib/libcygctl1.a`
- `/usr/lib/libcygnet.dll.a`
- `/usr/include/cygctl.h`
- `/usr/include/cygnet.h`
- `/usr/include/cygctl_compat.h`

## 使用

### 移植工具时

在 configure/Makefile 中加入：

```makefile
CFLAGS += -include cygctl_compat.h -I/usr/include
LIBS   += -lcygctl1 -lcygnet
```

### 接口名映射（cygnet）

```c
#include <cygnet.h>

char npf[256];
cygnet_ifname_to_npf("eth0", npf, sizeof(npf));
// npf = "\Device\NPF_{3B4...}"
```

### 高层网络操作（cygctl1）

```c
#include <cygctl.h>

cygctl_init();

// 扫描器
cygctl_scanner_t sc = cygctl_scanner_create(1000);
cygctl_scan_fire(sc, "192.168.1.1", 80, 3000);

cygctl_scan_result_t results[64];
int n = cygctl_scan_poll(sc, results, 64, 1000);

cygctl_scanner_destroy(sc);
cygctl_cleanup();
```

## 相关项目

- [cygctl](https://github.com/chen0430tw/cygctl) — Cygwin CLI 工具（cyg、apt-cyg、sudo、su）
