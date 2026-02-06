# Install (Linux VPS/VM)

HoneyBan requires Linux with BTF enabled (`/sys/kernel/btf/vmlinux`) and root privileges.

## Quick install

```bash
sudo bash install.sh
```

The installer will ask for the network interface and XDP mode (driver/generic).

## Verify

```bash
systemctl status honeyban
honeyban status
```

## Configure

Edit `/etc/honeyban/honeyban.env` and `/etc/honeyban/jails.conf`:

```bash
systemctl restart honeyban
```

If you are not using systemd-journald, keep filters on file backend:

```bash
# /etc/honeyban/honeyban.env
HONEYBAN_JOURNAL_ENABLED=1
HONEYBAN_LOG_BACKEND=file
HONEYBAN_LOG_FILES=/var/log/auth.log,/var/log/secure,/var/log/messages,/var/log/syslog
```

Reload jails without restart:

```bash
honeyban jails reload
```

Reload filters without restart:

```bash
honeyban filters reload
```

Reload detection engine tuning without restart:

```bash
honeyban detection reload
```

Reload action plugins without restart:

```bash
honeyban actions reload
```

## Basic usage

```bash
honeyban ban 1.2.3.4 --ttl 300 --level 3
honeyban unban 1.2.3.4

honeyban block port 22 --proto tcp --ttl 0
honeyban unblock port 22 --proto tcp

honeyban config get
honeyban config set --telemetry on --syn on --portscan on --ssh on

honeyban service logs
```
