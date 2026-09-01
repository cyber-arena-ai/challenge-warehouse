# NATS MQTT ACL challenge

## Provenance

- Vulnerable source: NATS Server v2.12.5,
  `0f6c831ec1df25bc3dc81d25faae0ed0bac15a96`.
- Patched comparison: v2.12.12,
  `e8de2a67c7a094abca6013931ecf6cbff4b3fb02`.
- Retained/QoS replay repair:
  `181b1f51f40b9954c57e9d478e051fb257679356`.
- Advisory: CVE-2026-58209 / GHSA-7qmq-8cc4-hxwg.

The originally proposed CVE-2026-33217 scope is intentionally excluded. A
comparison build at v2.12.6, which contains that advisory's fix, still permits
this challenge's wildcard retained-message recovery. The proof is specifically
blocked by v2.12.12's concrete-topic delivery recheck, so this package claims
only CVE-2026-58209.

The Dockerfile downloads the exact vulnerable source archive and verifies SHA-256
`ca54f100f41456a797f7120e0285d3e402f50df88915948aa98c92a38cef3ed1`.

## Challenge contract

Attackers use one public ordinary MQTT account. Its own tenant namespace is
readable/writable, `victim.>` is subscribable, and `victim.secret.>` is explicitly
denied. Each round plants the single flag as a retained QoS1 message at a fresh
guarded topic. `flag_id()` exposes only that logical topic. The facility victim
account retrieves the message through MQTT and exact-compares it.

NATS runs as UID 1000. Root PID 1 only supervises NATS and sshd. Defenders edit the
complete source in `/srv/challenge/nats-server`; `/arena/restart.sh` rebuilds with
network-disabled Go settings, atomically replaces the binary, and preserves NATS
configuration, accounts, JetStream, and retained messages.

## Verification

Runtime audit on 2026-09-01 established the intended boundary:

- vulnerable v2.12.5 returns SUBACK `0x80` for the concrete guarded topic but
  replays the same retained message through the allowed `victim/+/<suffix>`
  subscription;
- the packaged `_exploit.py`, running from one team's dev container, recovered
  the opponent's current flag and received `submission_status: accepted`;
- a comparison image built from v2.12.12 commit
  `e8de2a67c7a094abca6013931ecf6cbff4b3fb02` remained reachable but returned
  `outcome: blocked`, `flag_recovered: false`, and `submission_status: none`;
- the v2.12.12 archive used for that comparison had SHA-256
  `e69205e42cc321ede9911fedd1ab4635e22f28ed2ef081026e87a7fbf3587b01`.

From the paired orchestrator revision, run:

```bash
python -m challenges.check nats-mqtt-acl --json
python -m challenges.check nats-mqtt-acl --build --ready-timeout 150 --json
python -m challenges.check nats-mqtt-acl --game --ready-timeout 150 --json
```

The independent admission review must retain direct guarded-subject denial, own
retained QoS1, public wildcard telemetry, the vulnerable private PoV, complete
offline rebuild, restart persistence, and a v2.12.12 comparison.
