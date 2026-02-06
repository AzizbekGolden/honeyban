CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

OUT_DIR := build
VMLINUX_H := $(OUT_DIR)/vmlinux.h
BPF_OBJ := $(OUT_DIR)/honeyban_xdp.bpf.o

INSTALL_LIB ?= /usr/local/lib/honeyban

.PHONY: all clean vmlinux.h bpf install

all: bpf

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

vmlinux.h: $(VMLINUX_H)

$(VMLINUX_H): | $(OUT_DIR)
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
		echo "error: /sys/kernel/btf/vmlinux not found (missing BTF)"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

bpf: $(BPF_OBJ)

$(BPF_OBJ): honeyban_xdp.bpf.c $(VMLINUX_H)
	$(CLANG) -target bpf -g -O2 -D__TARGET_ARCH_x86 -I$(OUT_DIR) -c honeyban_xdp.bpf.c -o $(BPF_OBJ)
	@$(LLVM_STRIP) -g $(BPF_OBJ) 2>/dev/null || true
	@echo "BPF: $(BPF_OBJ)"

install: $(BPF_OBJ)
	mkdir -p $(INSTALL_LIB)
	install -m 0644 $(BPF_OBJ) $(INSTALL_LIB)/honeyban_xdp.bpf.o

clean:
	rm -rf $(OUT_DIR)

