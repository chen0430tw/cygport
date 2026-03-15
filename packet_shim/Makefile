# Packet.dll shim — MinGW-w64 (pure Windows DLL, no Cygwin)
CC     = x86_64-w64-mingw32-gcc
STRIP  = x86_64-w64-mingw32-strip

CFLAGS  = -O2 -Wall -Wextra -Wno-cast-function-type
LDFLAGS = -shared -Wl,--out-implib,libPacket.a

TARGET  = Packet.dll
SRC     = packet_shim.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lws2_32
	$(STRIP) $@
	@echo "Built: $(TARGET)"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "  OK /usr/local/bin/$(TARGET)"

clean:
	rm -f $(TARGET) libPacket.a

.PHONY: all install clean
