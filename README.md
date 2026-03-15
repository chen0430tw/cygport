# cygport

Cygwin 网络工具移植运行时。提供在 Cygwin 环境下移植 Linux 网络工具（nmap、tcpdump 等）所需的底层库和头文件。

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
