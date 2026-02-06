# Build Guide

This document explains fast local build and production build requirements for HoneyBan.

## Supported build host

- Linux only for full build (`core/daemon` + `core/bpf` + runtime).
- `core/cli` can be built on non-Linux development hosts.

## Required toolchain (Linux)

- `make`, `gcc`, `clang`, `llvm`
- `bpftool`
- `libbpf` and `libelf` development headers
- kernel headers for current kernel
- BTF enabled kernel (`/sys/kernel/btf/vmlinux` must exist)

On Debian/Ubuntu, `install.sh` installs these dependencies automatically.

## Fast build

From repo root:

```bash
make -C core/cli clean all
make -C core/daemon clean all
make -C core/bpf clean all
```

Combined build via top-level:

```bash
make -C core clean all
```

## Install artifacts (manual)

```bash
sudo make -C core install
```

Then install service/config templates:

```bash
sudo bash install.sh
```

## Build profiles

- Performance-first runtime: `HONEYBAN_PROFILE=fast`
- Detection-first runtime: `HONEYBAN_PROFILE=accurate`
- Full manual tuning: `HONEYBAN_PROFILE=custom`

## Common build issues

### `bpf/libbpf.h: file not found`

Install `libbpf` dev package:

- Debian/Ubuntu: `libbpf-dev`
- Fedora/RHEL/CentOS: `libbpf-devel`

### Missing BTF

If `/sys/kernel/btf/vmlinux` is missing, use a kernel with BTF enabled or install the matching debug/BTF package for your distro.

### XDP attach fails

- Try fallback mode: `HONEYBAN_XDP_MODE=generic`
- Verify NIC/driver XDP support.
- Ensure you run as root.

## Validation

After install:

```bash
systemctl status honeyban
honeyban status
honeyban config get
```

For logs:

```bash
honeyban service logs
```
