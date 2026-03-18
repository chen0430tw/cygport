# John the Ripper Jumbo Cygwin 移植记录

**版本**：bleeding-jumbo (1.9.0-jumbo-1+bleeding-d8f5b0138e6，2026-02-22)
**平台**：Cygwin (x86_64-pc-cygwin)，GCC 13.4.0
**日期**：2026-03-18

---

## 结果

```
john --list=build-info
→ Version: 1.9.0-jumbo-1+bleeding-d8f5b0138e6
→ Build: cygwin 64-bit x86_64 AVX-512 AC OMP OPENCL

rar2john test_encrypted.rar
→ $RAR3$*0*45b53a768caf05eb*0d96d610eced47f85696fcff2e0ccd44:...

全部 26 个工具编译完成，含 rar2john / zip2john / gpg2john / keepass2john
                              / vncpcap2john / SIPdump / eapmd5tojohn（npcap）
1 个源码 patch，port.sh john 一键通过
```

---

## 依赖安装

```bash
# Cygwin 官方仓库依赖
apt install libssl-devel libgmp-devel libbz2-devel gcc-core gcc-g++ make gendef
```

### OpenCL（GPU 格式支持）

```bash
# 从 CUDA toolkit 复制 CL 头文件
sudo mkdir -p /usr/local/include/CL
sudo cp "/cygdrive/c/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.1/include/CL/"*.h \
        /usr/local/include/CL/

# 从 System32/OpenCL.dll 生成 import lib
sudo cp /cygdrive/c/Windows/System32/OpenCL.dll /tmp/
(cd /tmp && gendef OpenCL.dll && dlltool -D OpenCL.dll -d OpenCL.def -l /usr/local/lib/libOpenCL.a)
```

### npcap（vncpcap2john / SIPdump / eapmd5tojohn）

```bash
# 下载 npcap SDK 并解压到 /cygdrive/c/cygwin64/tmp/npcap-sdk/
# 安装头文件
sudo cp -r /cygdrive/c/cygwin64/tmp/npcap-sdk/Include/pcap /usr/local/include/
sudo cp /cygdrive/c/cygwin64/tmp/npcap-sdk/Include/pcap.h /usr/local/include/
sudo cp /cygdrive/c/cygwin64/tmp/npcap-sdk/Include/pcap-bpf.h /usr/local/include/

# 从 System32/Npcap/*.dll 生成 import libs
sudo cp /cygdrive/c/Windows/System32/Npcap/wpcap.dll /tmp/
sudo cp /cygdrive/c/Windows/System32/Npcap/Packet.dll /tmp/
(cd /tmp && gendef wpcap.dll && dlltool -D wpcap.dll -d wpcap.def -l /usr/local/lib/libwpcap.a)
(cd /tmp && gendef Packet.dll && dlltool -D Packet.dll -d Packet.def -l /usr/local/lib/libPacket.a)
```

configure 检测结果：

| 功能 | 状态 |
|------|------|
| OpenSSL（大量格式支持）| ✅ |
| libgmp（PRINCE 模式）| ✅ |
| libz（7z / pkzip）| ✅ |
| libbz2（7z / gpg2john）| ✅ |
| Non-free unrar（完整 RAR 支持）| ✅（源码自带）|
| OpenMP | ✅ |
| Fork | ✅ |
| OpenCL | ✅（CUDA OpenCL.dll + CL 头文件）|
| libpcap | ✅（npcap SDK + wpcap.dll）|

---

## 编译命令

```bash
cd src
# configure 不带 npcap/OpenCL 路径（避免干扰标准头文件检测）
LDFLAGS='-L/usr/local/lib' ./configure
# make 时再加头文件路径
make -j4 CPPFLAGS='-I/usr/local/include'
```

输出在 `../run/` 目录。

---

## 遇到的问题与解法

### 问题 1：strncasecmp/strcasecmp const 不匹配

**现象**：`jumbo.c:272: error: conflicting types for 'strncasecmp'`

**原因**：npcap 头文件中 `strncasecmp` 声明使用 `const char*`，但 john 原始实现用 `char*`，触发条件是 `NEED_STRNCASECMP_NATIVE=1`（Cygwin + npcap 才会触发）。

**解法**：`0001-fix-strncasecmp-const.patch` — 给 jumbo.c 的实现加 `const`。

### 问题 2：configure 的 CPPFLAGS 不能带 npcap 路径

**现象**：将 `-I/usr/local/include` 加到 configure 的 CPPFLAGS 后，autoconfig.h 中几乎所有 `HAVE_` 标志全部变成 `#undef`（包括 stdlib.h、unistd.h、string.h 等标准库）。

**原因**：npcap 头文件（尤其是 `pcap/pcap-inttypes.h`）干扰了 configure 的测试程序编译，导致 configure 误判所有标准头文件不存在。

**解法**：configure 不带 `-I/usr/local/include`，只在 make 时传入：
```bash
LDFLAGS='-L/usr/local/lib' ./configure          # configure 正常检测
make -j4 CPPFLAGS='-I/usr/local/include'         # make 时才加 npcap/OpenCL 路径
```

---

## 编译产物（run/ 目录，共 26 个工具）

| 工具 | 用途 |
|------|------|
| `john.exe` | 主程序（含 OpenCL GPU 格式）|
| `rar2john.exe` | 从 RAR 文件提取哈希 |
| `zip2john.exe` | 从 ZIP 文件提取哈希 |
| `gpg2john.exe` | 从 GPG 密钥提取哈希 |
| `keepass2john.exe` | 从 KeePass 数据库提取哈希 |
| `wpapcap2john.exe` | 从 WPA 握手包提取哈希（需 npcap）|
| `vncpcap2john.exe` | 从 VNC pcap 提取哈希（需 npcap）|
| `SIPdump.exe` | 从 SIP pcap 提取哈希（需 npcap）|
| `eapmd5tojohn.exe` | 从 EAP-MD5 pcap 提取哈希（需 npcap）|
| `bitlocker2john.exe` | 从 BitLocker 卷提取哈希 |
| `dmg2john.exe` | 从 macOS DMG 提取哈希 |
| `putty2john.exe` | 从 PuTTY 私钥提取哈希 |
| `unshadow.exe` | 合并 /etc/passwd 和 /etc/shadow |
| `unique.exe` | 字典去重 |

---

## 验证（RAR 破解测试）

```bash
# 创建加密 RAR（密码：abc123）
"/c/Program Files/WinRAR/rar.exe" a -hpabc123 -ma3 test.rar test.txt

# 提取哈希
rar2john test.rar
# → $RAR3$*0*45b53a768caf05eb*0d96d610eced47f85696fcff2e0ccd44

# 用 hashcat 破解（更快）
hashcat -m 12500 -a 0 rar.hash rockyou.txt --force
# → abc123（1 秒，RTX 3070 @ 2447 H/s）
```

---

## 自动化（port.sh 流程）

```bash
cd /cygdrive/d/cygport
bash port.sh john          # 完整流程：download → apply → build → install
```

分步：

```bash
bash port.sh john --download   # 下载 bleeding-jumbo.tar.gz
bash port.sh john --apply      # 安装 OpenCL/npcap 前置 + 应用 patch
bash port.sh john --build      # configure + make
bash port.sh john --install    # 安装到 /usr/local/share/john/ + wrapper
bash port.sh john --clean      # 清除构建目录
```

**配置文件**：`D:\cygport\patches\john\pkg.conf`

安装后所有工具通过 wrapper 在任意目录可用：

```bash
john --list=build-info
rar2john file.rar
zip2john file.zip
vncpcap2john capture.pcap
```

---

## Patch 列表

| 文件 | 作用 |
|------|------|
| `0001-fix-strncasecmp-const.patch` | jumbo.c strncasecmp/strcasecmp 加 const，解决与 npcap 头文件的声明冲突 |

---

## 关于 rar2john 来源

Cygwin 官方仓库无 John the Ripper（自由软件审查问题），WSL 的 Ubuntu 官方源只有 john 1.8.0（太旧，不含 rar2john）。

解法对比：

| 方式 | 状态 |
|------|------|
| `apt install john`（Cygwin）| ❌ 不在仓库 |
| `apt install john`（WSL Ubuntu）| ❌ v1.8.0，无 rar2john |
| `snap install john-the-ripper`（WSL）| ✅ 可用，但依赖 WSL |
| 本次移植（Cygwin 本地编译）| ✅ 原生，含 OpenCL + npcap |

---

## 文件位置

| 路径 | 内容 |
|------|------|
| `/usr/local/share/john/` | john 安装目录（run/ 内容）|
| `/usr/local/bin/john` | wrapper script |
| `/usr/local/bin/rar2john` | wrapper script |
| `/usr/local/bin/vncpcap2john` | wrapper script |
| `/usr/local/lib/libOpenCL.a` | 从 System32/OpenCL.dll 生成 |
| `/usr/local/lib/libwpcap.a` | 从 System32/Npcap/wpcap.dll 生成 |
| `/usr/local/include/CL/` | CUDA toolkit OpenCL 头文件 |
| `/usr/local/include/pcap.h` | npcap SDK 头文件 |
| `D:\cygport\patches\john\pkg.conf` | port.sh 配置 |
| `D:\cygport\patches\john\apply.sh` | 前置安装脚本 |
| `D:\cygport\patches\john\0001-fix-strncasecmp-const.patch` | 源码 patch |
