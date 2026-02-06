# HoneyBan

HoneyBan is an eBPF/XDP firewall and intrusion-response system focused on high-speed blocking at kernel ingress, with Fail2Ban-style policy control in userspace.

[honeyban.com](https://honeyban.com)

## Key capabilities

- XDP packet drop path (before the full Linux network stack).
- C-based daemon + CLI with Unix socket API.
- Per-service jail model (`maxretry`, `findtime`, `bantime`, `ignoreip`, ports, protocol).
- Regex filter engine with:
  - `journal` backend (systemd-journald)
  - `file` backend (`/var/log/...` tail)
  - `auto` backend (journal first, then file fallback)
- Extended filter DSL:
  - `regex`, `regexi`
  - `ignoreregex`, `ignoreregi`
  - `datepattern` (`none|syslog|iso8601|custom-regex`)
- Action plugin framework (`actions.d`) with async command hooks and builtin actions:
  - `banip`
  - `banipport`
  - `blockport`
- Detection engine (confidence + risk score + decay) to reduce false positives before jail action.

## Architecture

1. Packet enters NIC.
2. XDP program checks ban/allow maps and fast detector paths.
3. Userspace daemon receives telemetry/log signals.
4. Detection engine scores source risk.
5. Jail policy decides threshold/action.
6. Action updates BPF maps (and optional action hook command).

## Why HoneyBan vs traditional userspace blocking

- Blocking happens earlier in the packet path (XDP), reducing CPU pressure during attack bursts.
- BPF map lookups are constant-time and avoid repeated firewall rule traversal.
- Single control plane for packet telemetry + auth-failure logs + policy actions.
- Designed for low-latency response on small VPS and high-traffic hosts.

## Fail2Ban comparison

### HoneyBan advantages

- Earlier drop point: XDP can reject malicious traffic before iptables/nftables chains.
- Better flood posture: SYN/portscan handling includes kernel-path controls.
- Unified signal model: combines packet-level and log-level detections.
- Lower runtime overhead under heavy connection churn due to BPF map-driven enforcement.
- Extensible action model with async command hooks (`actions.d`).

### Fail2Ban advantages

- Larger and older filter ecosystem across many services and distributions.
- More mature operational footprint in legacy environments.
- Broader default packaging in distro repositories.

### Practical guidance

- If you need maximum ingress performance and kernel-level drop, HoneyBan is the stronger model.
- If you need immediate compatibility with niche legacy log formats out of the box, Fail2Ban may require less initial tuning.

## Fast install (production VPS)

Run on Linux only (XDP is not available on macOS kernel).

```bash
sudo bash install.sh
```

Verify:

```bash
systemctl status honeyban
honeyban status
```

## Fast build from source

See full details in `docs/BUILD.md`.

Quick commands:

```bash
make -C core/cli clean all
make -C core/bpf clean all
make -C core/daemon clean all
```

## Production checklist

- Use native XDP mode when supported: `HONEYBAN_XDP_MODE=driver`.
- Keep `HONEYBAN_LOG_BACKEND=auto` for portability across systemd/non-systemd hosts.
- Set explicit `ignoreip` ranges per jail.
- Tune `maxretry/findtime/bantime` by service, not globally.
- Keep action hooks short and bounded with `HONEYBAN_ACTION_CMD_TIMEOUT_MS`.
- Start with conservative filter rules (`prefilter` + specific `regex` + `ignoreregex`).
- Run with telemetry disabled on throughput-critical hosts unless needed for userspace detectors.

## Common CLI operations

```bash
honeyban ban 1.2.3.4 --ttl 300 --level 3
honeyban ban ip-port 1.2.3.4 22 --proto tcp --ttl 600 --level 3
honeyban block port 22 --proto tcp --ttl 0
honeyban whitelist add 10.0.0.1
honeyban config get
honeyban jails reload
honeyban filters reload
honeyban detection reload
honeyban actions reload
honeyban service logs
```

## Repository layout

- `core/bpf`: eBPF/XDP program (`honeyban_xdp.bpf.o`)
- `core/daemon`: `honeyban-daemon` (C, libbpf)
- `core/cli`: `honeyban` CLI (C)
- `core/integrations`: optional integrations (OpenResty/Lua sample)
- `core/packaging`: systemd unit + config templates
- `website`: static site for honeyban.com

## Documentation index

- `docs/BUILD.md`
- `docs/INSTALL.md`
- `docs/CONFIG.md`
- `docs/JAILS.md`
- `docs/FILTERS.md`
- `docs/DETECTION.md`
- `docs/ACTIONS.md`
- `docs/PROFILES.md`

## License

- Userspace code and website: MIT.
- eBPF program uses a GPL-compatible license string (`Dual BSD/GPL`) for kernel helper compatibility.
