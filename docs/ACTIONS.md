# Actions (plugin framework)

HoneyBan supports Fail2Ban-style action plugins via `actions.d`.

## Directory

- Default: `/etc/honeyban/actions.d`
- Override: `HONEYBAN_ACTIONS_DIR`

Reload without restart:

```bash
honeyban actions reload
```

## File format

Each `*.conf` is INI.
Each section name is the action name used in `jails.conf`:

```ini
[banip-notify]
enabled=on
base=banip
ban_cmd=logger "honeyban jail={jail} ip={ip}"
timeout_ms=1000
```

## Keys

- `enabled`: `on|off`
- `base`: `none|banip|banipport|blockport`
- `ban_cmd`: shell command template executed asynchronously
- `timeout_ms`: command timeout (`10..30000`)

## Template variables

- `{action}` `{jail}` `{filter}`
- `{ip}` `{proto}` `{port}`
- `{ttl}` `{level}`

## Notes

- Built-in actions still work directly: `banip`, `banipport`, `blockport`.
- Custom action names are resolved from `actions.d`.
- Command hooks run in background worker queue so jail detection path stays fast.
