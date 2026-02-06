# Jails (Fail2Ban-style policy)

HoneyBan uses a simple **jail model** to make detection and response service-scoped, similar to Fail2Ban.

Each jail can have its own:

- `maxretry` / `findtime` / `bantime`
- `ignoreip` list (IP/CIDR)
- protocol/ports scope
- action (`banip`, `banipport`, `blockport`)

This avoids the “one global threshold for everything” problem and keeps false positives low.

## File location

- Default: `/etc/honeyban/jails.conf`
- Override: set `HONEYBAN_JAILS_PATH` in `/etc/honeyban/honeyban.env`

Reload without restart:

```bash
honeyban jails reload
```

## Format

`jails.conf` is INI:

- Each `[section]` is a jail name.
- Each line is `key=value`.
- Comments start with `;` or `#`.

## Keys

### Core

- `enabled`: `on|off`
- `detector`: `journal|ssh|portscan|synflood`
- `action`: `banip|banipport|blockport` or custom action name from `actions.d`
- `filter`: filter name (only for `detector=journal`)

Custom action definitions are in `/etc/honeyban/actions.d/*.conf` (see `docs/ACTIONS.md`).

### Thresholds (Fail2Ban-like)

- `maxretry`: integer threshold
- `findtime`: seconds window
- `bantime`: seconds (0 = permanent)
- `ban_level`: 1..5 (severity label; used for telemetry/labels)

### Scope filters

- `protocol`: `tcp|udp|any` (default `any`)
- `ports`: comma-separated list (e.g. `22,80,443`)
- `ignoreip`: comma-separated IP or CIDR list

## Examples

### SSH brute force (recommended)

```ini
[ssh]
enabled=on
detector=journal
filter=sshd
action=banip
maxretry=5
findtime=60
bantime=3600
protocol=tcp
ports=22
ignoreip=10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.1/32,::1/128
```

Notes:

- HoneyBan uses regex filters from log backend (`journal` or file-tail fallback) for SSH auth failures.
- If journald is not available, SSH can still be detected by TCP connect-rate (`detector=ssh`, telemetry required).

### Port scan

```ini
[portscan]
enabled=on
detector=portscan
action=banip
maxretry=20
findtime=10
bantime=600
protocol=tcp
```

### SYN flood (per source)

```ini
[synflood]
enabled=on
detector=synflood
action=banip
maxretry=200
findtime=1
bantime=300
protocol=tcp
```
