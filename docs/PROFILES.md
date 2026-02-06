# Profiles

HoneyBan supports three profiles:

## fast

- Maximum throughput
- XDP only (no telemetry, no detectors)

## accurate

- Telemetry + userspace detectors enabled
- Conservative thresholds to reduce false positives
- Journald regex filters enabled (for SSH auth failures when systemd is available)

## custom

- Use your own values from `/etc/honeyban/honeyban.env`

Set profile in `/etc/honeyban/honeyban.env`:

```
HONEYBAN_PROFILE=accurate
```

Runtime switch (non-persistent):

```
honeyban profile fast
honeyban profile accurate
```
