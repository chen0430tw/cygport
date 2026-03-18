#!/bin/bash
# apply.sh — hashcat Cygwin patches
#
# v7.1.2 状态：
#   - lstdc++ 问题：已在上游修复（else 分支覆盖 CYGWIN）
#   - LTO 问题：通过 CFLAGS=-ffat-lto-objects 在 pkg_build() 中解决，无需 patch
#
# 如果未来升级到修复前的版本（存在 per-platform ifeq 链），
# 在此处加回 CYGWIN -lstdc++ patch。

set -euo pipefail
echo "[hashcat] No source patches required for v7.1.2."
