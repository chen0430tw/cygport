# Metasploit Cygwin 移植文档

*Metasploit Framework — Cygwin/Windows 移植记录*

---

## 背景

Metasploit Framework 是 Ruby 编写的渗透测试框架，依赖多个原生 C 扩展（.so/.bundle）。
在 Cygwin 上运行的核心障碍是这些 C 扩展需要针对 Cygwin/Windows 重新编译，
其中部分扩展用到了只有 Linux/BSD 才有的系统调用或库。

移植策略：逐个攻破 C 扩展依赖，其余纯 Ruby 代码无需修改。

### 调研说明

网上资料（GitHub issue、StackOverflow）普遍将 Cygwin 和原生 Windows（MinGW/MSVC）混为一谈，
导致 eventmachine、ffi、msgpack 等看起来"不支持 Windows"——实际上它们只是不支持原生 Windows，
Cygwin 是 POSIX 环境，`gem install` 直接编译即可。

**结论：网上调研只作参考，手工编译实测才算数。**

---

## 依赖移植进度

### 可通过 apt 直接安装（无需移植）

```bash
apt install ruby-pg ruby-nokogiri ruby-bcrypt ruby-sqlite3 ruby-oj ruby-mysql2 \
            ruby-nio4r ruby-puma ruby-websocket-driver ruby-redis
```

| Gem | 说明 |
|-----|------|
| ruby-pg | PostgreSQL 扩展 |
| ruby-nokogiri | HTML/XML 解析 |
| ruby-bcrypt | 密码哈希 |
| ruby-sqlite3 | SQLite3 扩展 |
| ruby-oj | 快速 JSON |
| ruby-mysql2 | MySQL 扩展 |
| ruby-nio4r | 异步 I/O |
| ruby-puma | HTTP 服务器 |
| ruby-websocket-driver | WebSocket |
| ruby-redis | Redis 客户端 |
| ruby-json | Ruby 3.2 内建，无需安装 |

### 需要移植的 C 扩展

| 扩展 | 版本 | 状态 | 说明 |
|------|------|------|------|
| pcaprub | 0.13.3 | ✅ 完成 | libpcap 绑定，改走 Npcap SDK |
| eventmachine | 1.2.7 | ✅ 零修改 | 已有 `/cygwin/` 分支，Cygwin OpenSSL 自动检测 |
| ffi | 1.17.3 | ✅ 零修改 | 使用系统 libffi，Cygwin 走 libffi.mk |
| msgpack | 1.8.0 | ✅ 零修改 | 纯标准 C，无平台特定代码 |

### 纯 Ruby gem（直接 gem install）

| Gem | 版本 | 说明 |
|-----|------|------|
| packetfu | 2.0.0 | 纯 Ruby 网络包操作库，无 C 扩展 |

```bash
gem install packetfu -v 2.0.0
```

---

## 安装前置作业

### Windows Defender 排除项

Metasploit 包含真实 exploit payload 和 shellcode，Defender 会持续报威胁并可能删除文件。
安装前必须先将目录加入排除列表：

```powershell
# 需要管理员权限，可用 cygctl sudo 执行
sudo powershell -Command "Add-MpPreference -ExclusionPath 'C:\Users\asus\metasploit-framework'"

# 验证
sudo powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
```

这不是误报——Defender 在正确工作，Metasploit 本身就包含恶意代码（用于合法渗透测试）。

**gem 安装路径也需要排除**（bundle install 期间 Defender 可能删除 payload 相关文件）：

```powershell
sudo powershell -Command "Add-MpPreference -ExclusionPath 'C:\cygwin64\usr\share\gems'"
sudo powershell -Command "Add-MpPreference -ExclusionPath 'C:\cygwin64\usr\lib\gems'"
```

---

## pcaprub 0.13.3

### 作用

pcaprub 是 libpcap 的 Ruby C 扩展，Metasploit 用它实现网络捕包（`capture` 模块等）。
原版在 Cygwin 上编译失败：`extconf.rb` 的 Cygwin 分支走 Linux 路径，找不到 `libpcap`，
而 Cygwin 官方仓库也没有 libpcap 包。

### 调研方式

先在 WSL 中安装 pcaprub 获取源码，再复制到 Windows home 目录进行研究：

```bash
# WSL 内
gem install pcaprub
gem unpack pcaprub -v 0.13.3 --target=$HOME

# 复制到 Windows home 研究
cp -r ~/pcaprub-0.13.3 /mnt/c/Users/asus/
```

通过阅读 `ext/pcaprub_c/extconf.rb` 确认 Cygwin 走的是 Linux 路径（`else` 分支），
从而确定修法。

### 解决思路

Cygwin 已有 Npcap SDK（从 hping3/nmap 移植时安装到 `/opt/cygwin-port/`），
Npcap 提供 `wpcap.lib` / `libwpcap.a`，与 libpcap API 完全兼容。
MinGW 路径已经走 wpcap，只需给 Cygwin 加一个相同的分支即可。

### 补丁列表（共 2 个）

#### 0001-pcaprub-cygwin-extconf.patch

**文件**：`ext/pcaprub_c/extconf.rb`

**问题**：`extconf.rb` 的 `else` 分支（Linux/macOS/Cygwin 均走此分支）
查找 `libpcap`，Cygwin 上不存在，直接失败。

**修法**：在 `elsif /x64-mswin32/` 之后、`else` 之前插入 Cygwin 分支：

```ruby
elsif /cygwin/ =~ RUBY_PLATFORM
  default_cygwin_sdk = '/opt/cygwin-port'

  pcap_dir        = with_config("pcap-dir", default_cygwin_sdk)
  pcap_includedir = with_config("pcap-includedir", pcap_dir + "/include")
  pcap_libdir     = with_config("pcap-libdir", pcap_dir + "/lib")

  $CFLAGS  = "-DWIN32 -I#{pcap_includedir}"
  $LDFLAGS = "-L#{pcap_libdir}"

  have_header("ruby/thread.h")
  have_func("rb_thread_blocking_region")
  have_func("rb_thread_call_without_gvl")
  have_library("wpcap", "pcap_open_live")
  have_library("wpcap", "pcap_setnonblock")
```

`-DWIN32` 的目的：让 pcaprub.c 的 WIN32 条件编译分支生效（使用 `pcap_sendpacket`、`pcap_getevent`、`WaitForSingleObject` 等 Windows API），与 MinGW 构建路径保持一致。

#### 0002-pcaprub-cygwin-win32-guards.patch

**文件**：`ext/pcaprub_c/pcaprub.c`

**问题 1**：`#if defined(WIN32)` 块内使用 `HANDLE`、`WaitForSingleObject`、`pcap_getevent` 等 Windows 类型，但 Cygwin 不像 MinGW 那样自动 include `<windows.h>`，导致 `HANDLE` 未定义。

**修法**：在文件顶部 WIN32-Extensions include 块之后加：

```c
#ifdef __CYGWIN__
  #include <windows.h>
#endif
```

**问题 2**：所有 `#if defined(WIN32)` 判断不包含 Cygwin，导致 Cygwin 走 Linux 路径（`pcap_get_selectable_fd`、`rb_thread_wait_fd`），但这些路径和 Npcap 不兼容。

**修法**：将以下 8 处 guard 全部改为 `#if defined(WIN32) || defined(__CYGWIN__)`：

| 位置 | 内容 |
|------|------|
| 前向声明 | `rbpcap_thread_wait_handle(HANDLE fno)` |
| monitor mode | 不支持，raise 错误 |
| inject | `pcap_sendpacket` vs `pcap_inject` |
| `each_data` HANDLE 声明 | `HANDLE fno` vs `int fno` |
| `each_data` getevent | `pcap_getevent` vs `pcap_get_selectable_fd` |
| `each_data` wait | `rbpcap_thread_wait_handle` vs `rb_thread_wait_fd` |
| `each_packet` 同上 | （同 each_data 两处） |
| 函数定义 | `rbpcap_thread_wait_handle_blocking` + `rbpcap_thread_wait_handle` |

### 编译警告说明

编译成功但有 3 个 warning，均不影响运行：

| warning | 原因 | 影响 |
|---------|------|------|
| `gettimeofday` 指针类型不兼容 | Npcap `pcap_pkthdr.ts` 是匿名 `bpf_timeval`，不是 POSIX `timeval` | 无，结构体内存布局相同 |
| `pcap_getevent` implicit declaration | Npcap SDK header 没导出该函数声明 | 无，linker 能找到符号 |
| int-to-pointer-cast | `pcap_getevent` 返回值转 `HANDLE` | 无，64-bit 下同宽 |

### 自动化

**路径**：`D:\cygport\patches\pcaprub\`

```
patches/pcaprub/
├── pkg.conf                              # 包描述
├── apply.sh                              # patch 应用脚本
├── 0001-pcaprub-cygwin-extconf.patch     # extconf.rb 修改
└── 0002-pcaprub-cygwin-win32-guards.patch # pcaprub.c 修改
```

**一键构建**：

```bash
bash /cygdrive/d/cygport/port.sh pcaprub
```

**构建流程**：
1. 从 rubygems.org 下载 `pcaprub-0.13.3.gem`
2. `gem unpack` 解压源码
3. 应用 2 个 patch
4. `ruby extconf.rb --with-pcap-dir=/opt/cygwin-port`
5. `make` → 生成 `pcaprub_c.so`
6. 安装到 `/usr/lib/ruby/vendor_ruby/3.2/`

**port.sh 新增功能**：`PKG_EXTRACT_CMD` 钩子，允许包自定义解压命令（gem 文件需要 `gem unpack` 而非 `tar`）。

### 运行时依赖

- Npcap（抓包必须，需开启 WinPcap 兼容模式）
- `/opt/cygwin-port/` 下的 Npcap SDK（编译时依赖，运行时不需要）
- `cygwin1.dll`（Cygwin 运行时）

### 验证结果

```ruby
require 'pcaprub'
PCAPRUB::Pcap.lookupdev
# => "\\Device\\NPF_{FA736F9F-7C01-4F32-BBB7-A8CB7FA3D0A5}"
```

`lookupdev` 直接返回 Npcap NPF 格式设备名，说明底层 Npcap 调用正常。

### 已知限制

- `pcap_getevent` 在 Npcap SDK header 中无声明，靠 implicit declaration 链接，理论上 Npcap 更新后 ABI 变化可能失效（实际上该函数极稳定）
- monitor mode 不支持（与 WinPcap/MinGW 构建行为相同）
- `each_data` / `each_packet` 的等待机制走 `WaitForSingleObject`，100ms poll 间隔，与 Linux 的 `select` 语义有差异

### bundle install 中的 pcaprub 安装问题

`bundle install` 会从 rubygems.org 下载原版 pcaprub 并尝试编译，但原版在 Cygwin 上编译失败（无 libpcap）。
编译失败后，gem 目录存在但缺少 `gem.build_complete`，导致 bundler 报 `GemNotFound`。

**解法**：先用 port.sh 编译打补丁版本，再手动注册到 Rubygems：

```bash
# 1. 用 port.sh 编译（如果 /tmp/cygport-work/pcaprub-0.13.3 已存在则跳过）
bash /cygdrive/d/cygport/port.sh pcaprub --build

# 2. 复制 .so 到 gem extensions 目录
cp /tmp/cygport-work/pcaprub-0.13.3/ext/pcaprub_c/pcaprub_c.so \
   /usr/lib/gems/ruby/3.2/pcaprub-0.13.3/

# 3. 标记扩展编译完成
touch /usr/lib/gems/ruby/3.2/pcaprub-0.13.3/gem.build_complete

# 4. 注册 gemspec（从原版 .gem 提取）
gem specification /tmp/cygport-work/pcaprub-0.13.3.gem --ruby \
   > /usr/share/gems/specifications/pcaprub-0.13.3.gemspec

# 5. 验证
gem list pcaprub
ruby -e "require 'pcaprub'; puts PCAPRUB::Pcap.lookupdev"
```

---

## Metasploit Framework 安装

### 前置依赖

```bash
# libyaml（psych gem 需要）
apt install libyaml-devel

# PostgreSQL 开发头文件（pg gem 需要）
apt install libpq-devel
```

### 安装步骤

```bash
# 1. Clone
git clone https://github.com/rapid7/metasploit-framework.git \
    /cygdrive/c/Users/asus/metasploit-framework
cd /cygdrive/c/Users/asus/metasploit-framework

# 2. bundle install（安装 244 个 gem）
bundle install

# 3. 修复 pcaprub（bundle 装的是未打补丁版，需手动注册我们的版本）
# 见上方 "bundle install 中的 pcaprub 安装问题"

# 4. 安装 packetfu（bundle 未处理）
gem install packetfu -v 2.0.0
```

### 验证启动

```bash
cd /cygdrive/c/Users/asus/metasploit-framework
ruby msfconsole --version
# Framework Version: 6.4.123-dev-fed897ae

echo 'exit' | ruby msfconsole -q
# 出现 msf > 提示符，exit code 0
```

### 已知 warning（不影响运行）

| Warning | 原因 | 影响 |
|---------|------|------|
| `Win32API is deprecated` | rex-core 使用旧 API | 无，仍可用 |
| `stty: Inappropriate ioctl` | 非交互式 tty | 交互模式下不出现 |
| `Unresolved or ambiguous specs: stringio` | 系统有两个 stringio 版本 | 无 |

---

## 功能验证 — 假靶机测试

### 假靶机（fake_target.py）

**位置**：`C:\Users\asus\fake_target.py`

模拟 5 个服务，用于验证 Metasploit 辅助模块在 Cygwin 上的网络功能：

| 端口 | 服务 | 模拟版本 | 实现方式 |
|------|------|---------|---------|
| 2121 | FTP | vsftpd 2.3.4 | 纯 Python socket |
| 8080 | HTTP | Apache 2.2.8 (Ubuntu) DAV/2 | 纯 Python socket |
| 2222 | SSH | OpenSSH 4.7p1 Debian-8ubuntu1 | paramiko（完整 key exchange）|
| 2323 | Telnet | Debian GNU/Linux 4.0 | 纯 Python socket + IAC 协商 |
| 2525 | SMTP | Postfix (Ubuntu) | 纯 Python socket |

SSH 使用 paramiko 完成真实的 key exchange，Metasploit 可获取完整加密算法表和 OS 指纹：

```bash
# 安装 paramiko（apt，对应 Python 3.9）
apt install python39-paramiko python39-cryptography -y
```

**启动靶机**（必须用 run_in_background，直接 `&` 后台进程会随 shell 退出被杀）：

```bash
# 在 Claude Code 中
cyg --exec "python3 /cygdrive/c/Users/asus/fake_target.py"
# 设 run_in_background=true

# 停止
cyg --exec "pkill -f fake_target.py"
```

### Metasploit 测试脚本（msf_test.rc）

**位置**：`C:\Users\asus\msf_test.rc`

```bash
ruby msfconsole -q -r /cygdrive/c/Users/asus/msf_test.rc
```

### 测试结果（7/7 通过）

| TEST | 模块 | 结果 |
|------|------|------|
| 1 | `scanner/portscan/tcp` | ✅ 5 端口全 OPEN |
| 2 | `scanner/ftp/ftp_version` | ✅ `vsFTPd 2.3.4` |
| 3 | `scanner/ftp/anonymous` | ✅ 正常执行，拒绝匿名 |
| 4 | `scanner/http/http_version` | ✅ `Apache/2.2.8 (Ubuntu) DAV/2` |
| 5 | `scanner/ssh/ssh_version` | ✅ `OpenSSH_4.7p1 Debian-8ubuntu1` + 加密算法表 + OS 识别 Ubuntu 8.04 |
| 6 | `scanner/smtp/smtp_version` | ✅ `Postfix (Ubuntu)` |
| 7 | `scanner/telnet/telnet_version` | ✅ `Debian GNU/Linux 4.0 localhost login:` |

SSH 模块输出示例：
```
SSH server version: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
  service.cpe23   cpe:/a:openbsd:openssh:4.7p1
  os.cpe23        cpe:/o:canonical:ubuntu_linux:8.04
  os.vendor       Ubuntu
  os.version      8.04
```

