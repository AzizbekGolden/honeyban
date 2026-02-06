# Filters (regex framework)

Fail2Ban has a large ecosystem of `filter.d` regex files. HoneyBan implements a similar model with two log backends:

- `journal`: systemd-journald stream (`SYSLOG_IDENTIFIER` + `MESSAGE`)
- `file`: tail regular log files (`/var/log/...`) and parse syslog-style service name
- `auto` (recommended): use `journal` when available, fallback to `file`

Filters live in `/etc/honeyban/filters.d/*.conf`.
Each filter uses regex to detect a security event and extract source IP.
Jails reference a filter via `detector=journal` + `filter=<name>`.

## Enable/disable

In `/etc/honeyban/honeyban.env`:

```
HONEYBAN_JOURNAL_ENABLED=1
HONEYBAN_FILTERS_DIR=/etc/honeyban/filters.d
HONEYBAN_LOG_BACKEND=auto
HONEYBAN_LOG_FILES=/var/log/auth.log,/var/log/secure,/var/log/messages,/var/log/syslog
HONEYBAN_LOG_READ_FROM_START=0
```

Reload without restart:

```bash
honeyban filters reload
```

## File format

Each `*.conf` is INI.

Each `[section]` is a **filter name**. Example: `[sshd]`.

### Keys

- `enabled`: `on|off`
- `syslog_identifier`: match service id (`SYSLOG_IDENTIFIER` in journald or parsed tag in file backend), example: `sshd`
- `prefilter`: comma-separated list of fast substrings; if none match, regex is skipped
- `ip_group`: capture group index that contains the IP (default `1`)
- `regex`: POSIX ERE pattern (case-sensitive)
- `regexi`: POSIX ERE pattern (case-insensitive)
- `ignoreregex`: POSIX ERE pattern; if matched, event is ignored
- `ignoreregi`: case-insensitive ignore regex
- `datepattern`: `none|syslog|iso8601|<custom-regex-prefix>`

### Requirements

- At least one regex must match and capture a valid IPv4 or IPv6 in `ip_group`.
- HoneyBan validates the extracted IP with `inet_pton` (invalid captures are ignored).

## Example: sshd

`/etc/honeyban/filters.d/sshd.conf`:

```ini
[sshd]
enabled=on
syslog_identifier=sshd
prefilter=Failed password,Invalid user,authentication failure,Failed publickey,maximum authentication attempts exceeded
ip_group=1
regex=Failed password for( invalid user)? .* from ([0-9A-Fa-f:.]+) port [0-9]+
regex=Invalid user .* from ([0-9A-Fa-f:.]+) port [0-9]+
regex=Failed publickey for( invalid user)? .* from ([0-9A-Fa-f:.]+) port [0-9]+
regex=maximum authentication attempts exceeded for .* from ([0-9A-Fa-f:.]+) port [0-9]+
regex=authentication failure;.* rhost=([0-9A-Fa-f:.]+)
ignoreregex=Accepted password for .*
```

## Built-in service filters

Package defaults now include:

- `sshd`
- `dropbear`
- `nginx-http-auth`
- `apache-basic-auth` / `httpd-basic-auth`
- `dovecot-auth`
- `postfix-sasl`
- `vsftpd-auth`
- `proftpd-auth`
- `pureftpd-auth`
- `openvpn-auth`
- `exim-auth`

These are conservative regexes with prefilters for speed and lower false positives.

## Accuracy + speed strategy

- Use `prefilter` for cheap substring gate first.
- Keep `regex` specific to auth-failure semantics.
- Add `ignoreregex` for known benign lines to reduce false positives.
- Use `datepattern=syslog` or `datepattern=iso8601` for raw file logs that start with timestamps.

## Wiring a filter to a jail

In `/etc/honeyban/jails.conf`:

```ini
[ssh]
enabled=on
detector=journal
filter=sshd
action=banip
maxretry=5
findtime=60
bantime=3600
ignoreip=10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
```
