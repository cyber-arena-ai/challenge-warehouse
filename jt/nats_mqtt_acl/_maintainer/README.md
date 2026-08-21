# NATS MQTT ACL challenge

## Provenance

- Vulnerable source: NATS Server v2.12.5,
  `0f6c831ec1df25bc3dc81d25faae0ed0bac15a96`.
- First comparison: v2.12.6,
  `0e0639058e0d2d8fce0cc34941f9897da152ab32`.
- Complete comparison: v2.12.12,
  `e8de2a67c7a094abca6013931ecf6cbff4b3fb02`.
- Original MQTT authorization repair:
  `3ca886f026903ab3010fa2e4fe5024603b6b98a0`.
- Retained/QoS replay repair:
  `181b1f51f40b9954c57e9d478e051fb257679356`.
- Advisories: CVE-2026-33217 / GHSA-jxxm-27vp-c3m5 and
  CVE-2026-58209 / GHSA-7qmq-8cc4-hxwg.

The Dockerfile downloads the exact vulnerable source archive and verifies SHA-256
`ca54f100f41456a797f7120e0285d3e402f50df88915948aa98c92a38cef3ed1`.

## Challenge contract

Every attacker receives a distinct deterministic MQTT account. Accounts have the
same role template: their own tenant namespace is readable/writable, `victim.>` is
subscribable, and `victim.secret.>` is explicitly denied. Each round plants the
READ flag as a retained QoS1 message at a fresh guarded topic. The target exposes
only that logical topic. The facility victim account retrieves the message through
MQTT and exact-compares it.

The EXECUTE flag is in `/opt/arena/objective/current`, root-only. The fixed setuid
helper accepts only real UID 1000 and the current operation id; direct reads, root,
the editable-source user, and stale/wrong operations fail. This follows the current
orchestrator submit/recover contract; the public model's observed-EXECUTE wording is
a known cross-repository mismatch and is not reimplemented here.

NATS runs as UID 1000. Root PID 1 only supervises NATS and sshd. Defenders edit the
complete source in `/srv/challenge/nats-server`; `/arena/restart.sh` rebuilds with
network-disabled Go settings, atomically replaces the binary, and preserves NATS
configuration, accounts, JetStream, retained messages, and objective state.

## Verification

From the paired orchestrator revision, run:

```bash
python -m challenges.check nats-mqtt-acl --json
python -m challenges.check nats-mqtt-acl --build --ready-timeout 150 --json
python -m challenges.check nats-mqtt-acl --game --ready-timeout 150 --json
```

The independent admission review must retain direct guarded-subject denial, both
same-role principals, own retained QoS1, public wildcard telemetry, victim control,
the vulnerable private PoV, direct backing-file denial, wrong/stale operation
negatives, complete offline rebuild, restart persistence, and the v2.12.6/v2.12.12
comparisons.
