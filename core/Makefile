.PHONY: all clean install uninstall

all:
	$(MAKE) -C bpf
	$(MAKE) -C daemon
	$(MAKE) -C cli

install:
	$(MAKE) -C bpf install
	$(MAKE) -C daemon install
	$(MAKE) -C cli install

uninstall:
	rm -f /usr/local/bin/honeyban
	rm -f /usr/local/bin/honeyban-daemon
	rm -f /usr/local/lib/honeyban/honeyban_xdp.bpf.o

clean:
	$(MAKE) -C bpf clean
	$(MAKE) -C daemon clean
	$(MAKE) -C cli clean

