#!/bin/bash
# apply.sh — john bleeding-jumbo Cygwin patches
#
# 源码无需修改，本脚本负责系统级前置工作：
#   1. OpenCL：从 CUDA toolkit 安装头文件，从 System32/OpenCL.dll 生成 libOpenCL.a
#   2. npcap：从 npcap SDK 安装头文件，从 System32/Npcap/wpcap.dll 生成 libwpcap.a
#
# 依赖（Cygwin apt）：
#   libssl-devel libgmp-devel libbz2-devel gcc-core gcc-g++ make gendef

set -euo pipefail

NPCAP_SDK="/cygdrive/c/cygwin64/tmp/npcap-sdk"
CUDA_CL="/cygdrive/c/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.1/include/CL"
INCLUDE_DIR="/usr/local/include"
LIB_DIR="/usr/local/lib"

# ── OpenCL 头文件 ────────────────────────────────────────────────
if [ ! -f "$INCLUDE_DIR/CL/cl.h" ]; then
    echo "[john] Installing OpenCL headers from CUDA toolkit..."
    sudo mkdir -p "$INCLUDE_DIR/CL"
    sudo cp "$CUDA_CL"/*.h "$INCLUDE_DIR/CL/"
else
    echo "[john] OpenCL headers already installed."
fi

# ── libOpenCL.a ──────────────────────────────────────────────────
if [ ! -f "$LIB_DIR/libOpenCL.a" ]; then
    echo "[john] Generating libOpenCL.a from System32/OpenCL.dll..."
    sudo cp /cygdrive/c/Windows/System32/OpenCL.dll /tmp/OpenCL.dll
    (cd /tmp && gendef OpenCL.dll && dlltool -D OpenCL.dll -d OpenCL.def -l "$LIB_DIR/libOpenCL.a")
else
    echo "[john] libOpenCL.a already exists."
fi

# ── npcap 头文件 ─────────────────────────────────────────────────
if [ ! -f "$INCLUDE_DIR/pcap.h" ]; then
    echo "[john] Installing npcap headers from SDK..."
    sudo mkdir -p "$INCLUDE_DIR/pcap"
    sudo cp -r "$NPCAP_SDK/Include/pcap" "$INCLUDE_DIR/"
    sudo cp "$NPCAP_SDK/Include/pcap.h" "$INCLUDE_DIR/"
    sudo cp "$NPCAP_SDK/Include/pcap-bpf.h" "$INCLUDE_DIR/"
else
    echo "[john] npcap headers already installed."
fi

# ── libwpcap.a / libPacket.a ─────────────────────────────────────
if [ ! -f "$LIB_DIR/libwpcap.a" ]; then
    echo "[john] Generating libwpcap.a from System32/Npcap/wpcap.dll..."
    sudo cp /cygdrive/c/Windows/System32/Npcap/wpcap.dll /tmp/wpcap.dll
    sudo cp /cygdrive/c/Windows/System32/Npcap/Packet.dll /tmp/Packet.dll
    (cd /tmp && gendef wpcap.dll && dlltool -D wpcap.dll -d wpcap.def -l "$LIB_DIR/libwpcap.a")
    (cd /tmp && gendef Packet.dll && dlltool -D Packet.dll -d Packet.def -l "$LIB_DIR/libPacket.a")
else
    echo "[john] libwpcap.a already exists."
fi

echo "[john] Prerequisites ready."

# ── 源码 patch ───────────────────────────────────────────────────
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"

# 修复 jumbo.c strncasecmp/strcasecmp const 不匹配
# npcap 头文件声明 const char*，但 jumbo.c 原始实现用 char*，导致编译冲突
patch -p1 < "$PATCH_DIR/0001-fix-strncasecmp-const.patch"

echo "[john] Source patches applied."
