# Vendored source — nautilus-institute/finals-2025 :: ico

This directory is a **vendored, committed** copy of the `ico/` challenge from
[nautilus-institute/finals-2025](https://github.com/nautilus-institute/finals-2025),
so the challenge builds on a fresh host with no out-of-band clone.

- **Upstream:** https://github.com/nautilus-institute/finals-2025
- **Pinned commit:** `366520c0cc43c08c0eaf0a9aadd3d813df01ce88`
- **License:** Apache-2.0 (see `LICENSE`)

Only `service/` (the Pascal sources the image build compiles) plus the upstream
`LICENSE`/`README`/`challenge_config.yaml` are vendored; the upstream `tests/`
icon fixtures and `poller/` are not used by our image and are omitted.

To upgrade the pin, run `scripts/sync_nautilus.sh` (in the orchestrator repo),
which re-materializes this directory from the upstream repo and reminds you to
update the pin constant in `challenge.py`.
