# Configuration

HoneyBan reads settings from `/etc/honeyban/honeyban.env` at startup (systemd `EnvironmentFile`).

Fail2Ban-style policy (per-service rules) lives in `/etc/honeyban/jails.conf` (see `docs/JAILS.md`).

## Interface and XDP mode

```
HONEYBAN_IFACE=eth0
HONEYBAN_XDP_MODE=driver   # driver|generic|hw
HONEYBAN_XDP_ENABLED=1
HONEYBAN_PROFILE=accurate # fast|accurate|custom
```

Notes:

- `driver` (native) is the fastest and recommended.
- `generic` uses skb mode (slower but works on more NICs).
- `HONEYBAN_XDP_FLAGS` can add extra numeric flags.
- `fast` disables detectors for maximum speed.
- `accurate` enables telemetry + detectors with conservative thresholds.
- `custom` uses explicit values below.

## Jails (policy)

```
HONEYBAN_JAILS_PATH=/etc/honeyban/jails.conf
```

Jails let you set different `maxretry/findtime/bantime/ignoreip/ports` per service, similar to Fail2Ban. See `docs/JAILS.md`.

## Filters (regex)

HoneyBan reads regex filters from:

```
HONEYBAN_FILTERS_DIR=/etc/honeyban/filters.d
HONEYBAN_JOURNAL_ENABLED=1
HONEYBAN_LOG_BACKEND=auto
HONEYBAN_LOG_FILES=/var/log/auth.log,/var/log/secure,/var/log/messages,/var/log/syslog
HONEYBAN_LOG_READ_FROM_START=0
```

Filters are consumed by log backend:

- `journal`: systemd-journald stream
- `file`: `/var/log` tail backend
- `auto`: journal first, file fallback

See `docs/FILTERS.md`.

## Actions (plugin framework)

```
HONEYBAN_ACTIONS_DIR=/etc/honeyban/actions.d
HONEYBAN_ACTION_CMD_TIMEOUT_MS=1000
```

Jails can use built-ins (`banip`, `banipport`, `blockport`) or custom action names loaded from `actions.d`.
See `docs/ACTIONS.md`.

## Detection engine

HoneyBan runs an internal detection pipeline before jail policy:

```
HONEYBAN_DET_MIN_CONFIDENCE=55
HONEYBAN_DET_HIGH_CONF_BYPASS=90
HONEYBAN_DET_SCORE_THRESHOLD=80
HONEYBAN_DET_DECAY_PER_SEC=2
HONEYBAN_DET_SYN_SCORE=8
HONEYBAN_DET_PORTSCAN_SCORE=20
HONEYBAN_DET_SSH_SCORE=30
HONEYBAN_DET_JOURNAL_SCORE=35
HONEYBAN_DET_FORWARD_COOLDOWN_SEC=1
```

This layer reduces false positives by combining per-signal confidence with per-source risk scoring (with decay over time). See `docs/DETECTION.md`.

## Telemetry and detectors

```
HONEYBAN_TELEMETRY=1
HONEYBAN_SYN_ENABLED=1
HONEYBAN_PORTSCAN_ENABLED=1
HONEYBAN_SSH_ENABLED=1
```

Telemetry powers userspace detectors and observability. For maximum throughput, set `HONEYBAN_TELEMETRY=0`.

Notes:

- `synflood` and `portscan` can still be enforced in-kernel (XDP fast-path) when their flags are enabled, even if telemetry is off.
- SSH auth failures via `detector=journal` do not require telemetry (but require `HONEYBAN_JOURNAL_ENABLED=1` and filters).

## Detector thresholds

```
HONEYBAN_SYN_THRESHOLD=200
HONEYBAN_SYN_WINDOW_SEC=1

HONEYBAN_PORTSCAN_THRESHOLD=20
HONEYBAN_PORTSCAN_WINDOW_SEC=10

HONEYBAN_SSH_THRESHOLD=8
HONEYBAN_SSH_WINDOW_SEC=120
```

These values are used as defaults for the built-in jails when `jails.conf` is missing (or empty). When you use `jails.conf`, put thresholds there for service-scoped tuning.

## Autoban action

```
HONEYBAN_AUTOBAN_LEVEL=3
HONEYBAN_AUTOBAN_TTL=600
```

## BPF object path (optional)

```
HONEYBAN_BPF_OBJ_PATH=/usr/local/lib/honeyban/honeyban_xdp.bpf.o
```
