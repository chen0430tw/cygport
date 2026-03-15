# CygNet Makefile
# Build: make
# Install: make install

CC      = gcc

# WinDivert (optional): set WINDIVERT_INC/WINDIVERT_LIB from cygport setup
WINDIVERT_INC ?= /opt/WinDivert/include
WINDIVERT_LIB ?=

CFLAGS  = -O2 -Wall -Wextra \
          -I./include \
          -I./src \
          -I/opt/npcap/Include \
          -I/opt/npcap/Include/pcap \
          -I/usr/include/w32api \
          -DWIN32_LEAN_AND_MEAN
# Add WinDivert include if available
ifneq ($(wildcard $(WINDIVERT_INC)/WinDivert.h),)
  CFLAGS += -I$(WINDIVERT_INC) -DHAVE_WINDIVERT
endif

LDFLAGS = -shared -Wl,--out-implib,libcygnet.dll.a

LIBS    = -liphlpapi -lws2_32
# Link WinDivert import lib if provided
ifneq ($(WINDIVERT_LIB),)
  LIBS += $(WINDIVERT_LIB)
endif

SRCS    = src/ifname.c \
          src/npcap_loader.c \
          src/windivert_pcap.c

OBJS    = $(SRCS:.c=.o)
TARGET  = cygnet.dll
IMPLIB  = libcygnet.dll.a

INSTALL_DLL = /usr/bin/$(TARGET)
INSTALL_LIB = /usr/lib/$(IMPLIB)
INSTALL_INC = /usr/include/cygnet.h

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $(TARGET)  import lib: $(IMPLIB)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -m 755 $(TARGET)  $(INSTALL_DLL)
	install -m 644 $(IMPLIB)  $(INSTALL_LIB)
	install -m 644 include/cygnet.h $(INSTALL_INC)
	@echo "  OK $(INSTALL_DLL)"
	@echo "  OK $(INSTALL_LIB)"
	@echo "  OK $(INSTALL_INC)"

clean:
	rm -f $(OBJS) $(TARGET) $(IMPLIB)

# ── Test tool ──────────────────────────────────────────────────────────────
test: test_ifname
	./test_ifname

test_ifname: test/test_ifname.c $(IMPLIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lcygnet -liphlpapi -lws2_32
