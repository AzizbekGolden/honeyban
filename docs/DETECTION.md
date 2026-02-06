# Detection Engine

HoneyBan detection flow is:

1. Signal input (`telemetry` or `journal filter`)
2. Confidence estimation per signal
3. Per-source risk score update (with time decay)
4. Forward to `jails` policy only if confidence/score gates pass

This separates noisy packet/log events from policy actions and reduces false positives.

## Signals

- `telemetry` (TCP SYN events): for `synflood` / `portscan` style behavior
- `journal filters` (regex matches): for service-specific auth failures (for example SSH)

## Scoring model

Per source IP, HoneyBan keeps an in-memory score:

- score increases by `signal_score * confidence`
- score decays every second (`HONEYBAN_DET_DECAY_PER_SEC`)
- high-confidence events can bypass score gate (`HONEYBAN_DET_HIGH_CONF_BYPASS`)

Forward condition:

- `confidence >= HONEYBAN_DET_MIN_CONFIDENCE`
- and (`confidence >= HONEYBAN_DET_HIGH_CONF_BYPASS` or `score >= HONEYBAN_DET_SCORE_THRESHOLD`)
- and optional cooldown check (`HONEYBAN_DET_FORWARD_COOLDOWN_SEC`)

## Tunables

In `/etc/honeyban/honeyban.env`:

```bash
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

## Runtime reload

After editing env values:

```bash
honeyban detection reload
```

No service restart is required for these parameters.

