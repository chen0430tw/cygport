# Makefile for cygctl1.dll
# 使用 MinGW-w64 编译，与 Cygwin 头文件完全隔离

CC = x86_64-w64-mingw32-gcc
AR = x86_64-w64-mingw32-ar
STRIP = x86_64-w64-mingw32-strip

# 编译选项
CFLAGS = -O2 -Wall -Wextra -DBUILDING_DLL
LDFLAGS = -shared -Wl,--out-implib,$(DISTDIR)/libcygctl1.a

# 链接库
LIBS = -lws2_32 -liphlpapi -lmswsock

# 目录
SRCDIR = src
INCDIR = include
OBJDIR = obj
DISTDIR = dist

# 源文件
SOURCES = $(SRCDIR)/cygctl_win32.c \
          $(SRCDIR)/cygctl_iocp.c \
          $(SRCDIR)/cygctl_raw.c \
          $(SRCDIR)/cygctl_route.c \
          $(SRCDIR)/cygctl_pcap.c \
          $(SRCDIR)/cygctl_win32_compat.c

# 目标文件
OBJECTS = $(OBJDIR)/cygctl_win32.o \
          $(OBJDIR)/cygctl_iocp.o \
          $(OBJDIR)/cygctl_raw.o \
          $(OBJDIR)/cygctl_route.o \
          $(OBJDIR)/cygctl_pcap.o \
          $(OBJDIR)/cygctl_win32_compat.o

# 目标
TARGET = $(DISTDIR)/cygctl1.dll
IMPLIB = $(DISTDIR)/libcygctl1.a
HEADER = $(INCDIR)/cygctl.h

# 默认目标
all: dirs $(TARGET) $(IMPLIB)

# 创建目录
dirs:
	@mkdir -p $(OBJDIR) $(DISTDIR)

# 编译目标文件
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADER) $(SRCDIR)/cygctl_internal.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# 链接 DLL
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)
	$(STRIP) $@

# 生成导入库
$(IMPLIB): $(TARGET)
	cp $(DISTDIR)/libcygctl1.a $(DISTDIR)/libcygctl1.a 2>/dev/null || true

# 安装到 Cygwin
install: $(TARGET)
	install -m 755 $(TARGET) /usr/bin/cygctl1.dll
	install -m 644 $(IMPLIB) /usr/lib/libcygctl1.a
	install -m 644 $(HEADER) /usr/include/cygctl.h
	install -m 644 $(INCDIR)/cygctl_compat.h /usr/include/cygctl_compat.h
	@echo "  OK /usr/bin/cygctl1.dll"
	@echo "  OK /usr/lib/libcygctl1.a"
	@echo "  OK /usr/include/cygctl.h"

# 安装到指定目录
install-to: $(TARGET)
	@echo "Installing to $(DESTDIR)..."
	@mkdir -p $(DESTDIR)/bin $(DESTDIR)/include
	cp $(TARGET) $(DESTDIR)/bin/
	cp $(HEADER) $(DESTDIR)/include/
	@echo "Installation complete."

# 清理
clean:
	rm -rf $(OBJDIR) $(DISTDIR)

# 重新编译
rebuild: clean all

# 测试编译
test: $(TARGET)
	@echo "Testing DLL load..."
	@file $(TARGET)
	@echo "Dependencies:"
	@x86_64-w64-mingw32-objdump -p $(TARGET) | grep "DLL Name"

# 显示帮助
help:
	@echo "cygctl1.dll Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build cygctl1.dll (default)"
	@echo "  install   - Install to /usr/bin and /usr/include"
	@echo "  install-to - Install to DESTDIR/bin and DESTDIR/include"
	@echo "  clean     - Remove build artifacts"
	@echo "  rebuild   - Clean and rebuild"
	@echo "  test      - Test DLL load and show dependencies"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  DESTDIR   - Installation directory (for install-to)"

.PHONY: all dirs install install-to clean rebuild test help
