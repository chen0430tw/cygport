# cygport — Top-level Makefile
#
# Builds all components:
#   cygctl1/   — MinGW-w64 runtime DLL (ARP, routing, raw sockets, IOCP scanner)
#   cygnet/    — Cygwin pcap abstraction (Npcap lazy-load + WinDivert fallback)
#
# Usage:
#   make           — build all
#   make cygctl1   — build only cygctl1.dll
#   make cygnet    — build only cygnet.dll
#   make install   — install both DLLs + headers to Cygwin
#   make clean     — remove build artifacts

.PHONY: all cygctl1 cygnet install clean

all: cygctl1 cygnet

cygctl1:
	$(MAKE) -C cygctl1

cygnet:
	$(MAKE) -C cygnet

install: all
	$(MAKE) -C cygctl1 install
	$(MAKE) -C cygnet install
	@echo ""
	@echo "Installing cygport headers..."
	install -d /usr/include
	install -m 644 include/cygctl_compat.h /usr/include/cygctl_compat.h
	@echo "  OK /usr/include/cygctl_compat.h"
	@echo ""
	@echo "cygport install complete."
	@echo "  cygctl1.dll -> /usr/bin/cygctl1.dll"
	@echo "  cygnet.dll  -> /usr/bin/cygnet.dll"
	@echo "  cygctl_compat.h -> /usr/include/"

clean:
	$(MAKE) -C cygctl1 clean
	$(MAKE) -C cygnet clean
