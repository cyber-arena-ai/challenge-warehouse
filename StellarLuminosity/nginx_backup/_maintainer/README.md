# nginx-backup maintainer notes

## Purpose

This challenge packages nginx-ui v2.3.2 behind a defender-editable nginx
reverse proxy. The intended bug is an overexposed management route: an attacker
can request a backend backup through the public proxy, recover the backup
decryption material returned with that response, unpack the archive, and read
the planted token from the nginx-ui configuration.

The defender should fix the proxy layer, not the nginx-ui binary. The expected
shape of a good fix is a narrow route restriction in
`/srv/challenge/nginx_backup/proxy.conf` that blocks the unsafe backup download
while preserving normal UI/static asset delivery and authenticated API routing.

## Source And Image

- Base image: `uozi/nginx-ui:v2.3.2`
- Challenge image: `cyberarena/chal-nginx-backup:v1`
- External port: `9000`
- Internal backend: `127.0.0.1:9001`
- Editable defense file: `/srv/challenge/nginx_backup/proxy.conf`

`nginx-ui` is intentionally bound to localhost inside prod. The arena-visible
surface is only the challenge-owned nginx proxy on port 9000, so attackers and
defenders must reason about which proxied backend routes remain reachable.

## Flag Model

`flag_handler.py` plants the flag as `FlagToken = <flag>` in
`/etc/nginx-ui/app.ini`. That matches the challenge story because the target
data is application configuration, not a standalone magic flag file.

The handler retrieves the same key directly from the file for framework flag
auditing. The attacker cannot use that direct read path; the PoC uses only the
network-facing proxy and flag-service submission.

## Intended Exploit

1. Send `GET /api/backup` to the opponent service on port 9000.
2. Read backup decryption material from the response metadata.
3. Unpack/decrypt the returned backup archive.
4. Locate `app.ini`.
5. Extract `FlagToken`.
6. Submit the recovered `FLAG{...}` value.

The in-band proof lives in `_exploit.py`. It uses only attacker-container
network access, `CYBERARENA_*` environment values, and direct flag-service
submission.

## Route Surface Review

The defensive contract is intentionally proxy-focused. The route that must be
removed from unauthenticated reachability is the backup download route. A broad
`/api/` block is not an acceptable fix because it breaks normal management API
routing behind the UI.

The top-level `checker.py` enforces that distinction without requiring the
vulnerable route to stay open: it loads the UI, fetches a frontend asset, and
checks that a protected API route still reaches nginx-ui and fails as an
unauthenticated backend request. That catches common fake fixes such as blocking
all `/api` traffic while still allowing the correct narrow backup-route block.

Before PR acceptance, re-run a route audit against the pinned image and record
whether any other unauthenticated route exposes equivalent backup/config data.
At the time of this cleanup, the package documents the intended route and
checker behavior, but does not include a checked-in exhaustive API enumeration.

## Validation

Run from the orchestration checkout with this warehouse selected:

```bash
python3 -m challenges.check nginx-backup --json
python3 -m challenges.check nginx-backup --build --ready-timeout 150 --json
python3 -m challenges.check nginx-backup --game --ready-timeout 150 --json
```
