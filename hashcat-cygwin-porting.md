# hashcat Cygwin 移植记录

**版本**：hashcat v7.1.2
**平台**：Cygwin (x86_64-pc-cygwin)，GCC 13.4.0
**GPU**：NVIDIA RTX 3070 8GB，CUDA + OpenCL
**日期**：2026-03-17

---

## 结果

```
hashcat --version   → v7.1.2
RTX 3070 RAR3-p     → 7060 H/s
全部 ~320 个模块编译完成，含 RAR3/RAR5
```

---

## 编译命令

```bash
cd /cygdrive/c/Users/asus/hashcat
CFLAGS='-ffat-lto-objects' LDFLAGS='-ffat-lto-objects' make ENABLE_LTO=1
```

运行时必须从 hashcat 目录启动（OpenCL kernel 路径是相对路径）：

```bash
cd /cygdrive/c/Users/asus/hashcat
./hashcat.exe -m 23800 -a 3 <hash> "?l?l?l?l"
```

---

## 依赖安装

```bash
# 官方 BUILD_CYGWIN.md 要求
apt install libiconv-devel gcc-core gcc-g++ make git python312 python312-devel
```

---

## 遇到的问题与解法

### 问题 1：LTO 并行分区失败（链接时 undefined reference）

**错误信息**：
```
/usr/lib/gcc/.../ld: /tmp/cc1DTq00.ltrans0.ltrans.o:<artificial>: undefined reference to `hashcat_init'
/usr/lib/gcc/.../ld: /tmp/cc1DTq00.ltrans0.ltrans.o:<artificial>: undefined reference to `hcmalloc'
...（数百条）
collect2: error: ld returned 1
make: *** [src/Makefile:902: hashcat.exe] Error 1
```

**根因**：

hashcat 默认开启 `-flto=auto`（并行 LTO）。LTO 的工作原理：

```
编译阶段：各 .c → .o（内含 LTO IR 中间码，而非直接机器码）
链接阶段：LTO 插件读取所有 .o 的 IR → 整体优化 → 切分区（partition）→ 各分区并行编译为机器码 → 最终链接
```

**Linux vs Cygwin 的差异**：

| 项目 | Linux | Cygwin |
|------|-------|--------|
| `.o` 格式 | ELF（含 `.gnu.lto_*` 节）| COFF（Windows PE 格式）|
| LTO 插件 | `liblto_plugin.so` | `cyglto_plugin.dll` |
| 小规模 LTO | ✅ | ✅ |
| 大型项目 LTO | ✅ | ❌ 分区间符号丢失 |

`cyglto_plugin.dll` 在处理 hashcat 这种规模（数百个 COFF 对象组成的静态库 `combined.NATIVE.a`）时，WPA（Whole Program Analysis）分区后跨分区符号 resolution 失败，导致 `ltrans*.o` 内大量 undefined reference。

**尝试过的方案**：
- `--param lto-partitions=1`（强制单分区）→ 仍失败，问题不在分区数量
- `ENABLE_LTO=0`（禁用 LTO）→ 能编过，但放弃了优化

**最终解法**：`-ffat-lto-objects`

参考 FlashAttention 的思路——不强制跨模块合并，让每个编译单元保留独立的机器码：

```
-ffat-lto-objects：每个 .o 同时存储 LTO IR + 普通机器码
效果：LTO 优化尽量做；IR 阶段解析失败的符号，链接器自动 fallback 到普通机器码
```

```bash
CFLAGS='-ffat-lto-objects' LDFLAGS='-ffat-lto-objects' make ENABLE_LTO=1
```

---

### 问题 2：`module_23800.dll`（RAR3-p Compressed）链接失败

**错误信息**：
```
ld: /tmp/cc9K9Mfp.ltrans7.ltrans.o: undefined reference to `__gxx_personality_seh0'
ld: libcygwin.a(_cygwin_crt0_common.o): undefined reference to `operator new(unsigned long)'
ld: undefined reference to `operator delete[](void*)'
```

**根因**：

hashcat 的 `src/Makefile` 在 `ENABLE_UNRAR=1` 时，对各平台加 `-lstdc++`（C++ 运行时），但 **CYGWIN 被漏掉了**：

```makefile
# Makefile 440-457 行（上游 bug）
ifeq ($(ENABLE_UNRAR),1)
  ifeq ($(UNAME),OpenBSD)
    LFLAGS += -lc++
  else ifeq ($(UNAME),Darwin)
    LFLAGS += -lstdc++
  else ifeq ($(UNAME),MSYS2)
    LFLAGS += -lstdc++
  else ifeq ($(UNAME),Linux)
    LFLAGS += -lstdc++
  # CYGWIN 没有！← bug
  endif
```

**解法**：patch `src/Makefile`，在 Linux 分支后加入 CYGWIN：

```makefile
else
ifeq ($(UNAME),CYGWIN)
LFLAGS                  += -lstdc++
endif
```

已 patch 的位置：`hashcat/src/Makefile` 第 453 行附近。

---

### 问题 3：unrar 不在 Cygwin 官方仓库

**现象**：`apt search unrar` 无结果

**原因**：

unrar（RARLAB）的许可证有一条限制：
> *源码不得用于重新创建 RAR 压缩算法*

这违反 FSF 自由软件定义，与 GPL 不兼容。Cygwin 官方仓库只收自由软件，没有 Debian 式的 `non-free` 隔离区。2010 年和 2013 年的两次 ITP（Intent to Package）均被拒。

**解法**：编译 hashcat 自带的 `deps/unrar/`

hashcat 在 `deps/unrar/` 内捆绑了 RARLAB 官方源码 v6.01，版本与 `module_23800` 的内部 API 适配，不要升级：

```bash
cd /cygdrive/c/Users/asus/hashcat/deps/unrar
make CXX=g++ CXXFLAGS='-O2' LIBFLAGS='' \
     DEFINES='-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP' \
     LDFLAGS='-pthread' STRIP=strip

cp unrar /usr/local/bin/unrar
unrar   # → UNRAR 6.01 freeware
```

---

## 自动化（port.sh 流程）

hashcat 已接入 `D:\cygport\port.sh` 自动化流水线，一条命令完成全流程：

```bash
cd /cygdrive/d/cygport
bash port.sh hashcat          # 完整流程：download → apply → build → install
```

也可分步执行：

```bash
bash port.sh hashcat --download   # 下载 v7.1.2.tar.gz
bash port.sh hashcat --apply      # 打补丁（v7.1.2 已无需，no-op）
bash port.sh hashcat --build      # 编译 hashcat.exe + deps/unrar/unrar
bash port.sh hashcat --install    # 安装到 /usr/local/share/hashcat/ + wrapper
bash port.sh hashcat --clean      # 清除构建目录
```

**配置文件**：`D:\cygport\patches\hashcat\pkg.conf`

| 字段 | 值 |
|------|----|
| `BUILD_TYPE` | `special`（自定义 `pkg_build()`）|
| 编译参数 | `CFLAGS/LDFLAGS='-ffat-lto-objects' make ENABLE_LTO=1` |
| 安装目标 | `/usr/local/share/hashcat/`（整目录结构）|
| wrapper | `/usr/local/bin/hashcat`（自动 cd 到安装目录）|

**port.sh 扩展**：为支持 hashcat 这类需要安装整个目录结构（而非单一二进制）的工具，新增了 `pkg_install()` hook。`pkg.conf` 中定义该函数后，`port.sh install` 会将控制权完全委托给它。

---

## 验证

```bash
cd /cygdrive/c/Users/asus/hashcat

# 版本
./hashcat.exe --version
# hashcat (v7.1.2)

# RAR 模块列表
./hashcat.exe -hh | grep -i rar
# 12500 | RAR3-hp
# 23700 | RAR3-p (Uncompressed)
# 23800 | RAR3-p (Compressed)
# 13000 | RAR5

# GPU benchmark（RTX 3070）
./hashcat.exe -m 23800 -a 3 \
  '$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33' \
  "?l?l?l?l" --force
# Speed.#*: 7060 H/s
# Hardware.Mon.#01: Temp: 61c
```

---

## 文件位置

| 路径 | 内容 |
|------|------|
| `C:\Users\asus\hashcat\` | hashcat 源码 + 编译产物 |
| `C:\Users\asus\hashcat\hashcat.exe` | 主程序 |
| `C:\Users\asus\hashcat\modules\` | ~320 个哈希模块 `.dll` |
| `C:\Users\asus\hashcat\src\Makefile` | 已 patch（CYGWIN -lstdc++）|
| `C:\Users\asus\hashcat\deps\unrar\` | unrar 源码（v6.01）|
| `/usr/local/bin/unrar` | 编译好的 unrar 独立二进制 |

---

## 已知限制

- **必须从 hashcat 目录运行**：OpenCL kernel（`OpenCL/` 目录）路径是相对路径，从其他目录调用会报 `inc_vendor.h not found`
- **p7zip（Cygwin 版）已损坏**：Cygwin 官方 p7zip 包是 Unmaintained，wrapper 脚本指向不存在的 `.exe`，不可用
