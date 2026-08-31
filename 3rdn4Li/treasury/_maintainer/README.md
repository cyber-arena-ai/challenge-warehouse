# Maintainer helpers — NOT challenge artifacts

The files in this folder are **not** part of the challenge. They exist only to
make reviewing and running this PR easier and can be deleted after merge —
nothing in the challenge package imports them.

## Security contract

The flag is stored as a treasure description under a random 60-character
location key.  That key remains inside the opaque facility handle so
`retrieve()` can check persistence, but it is deliberately not returned by
`FlagHandler.flag_id()`.  Publishing it would make the normal `view <key>`
command a no-vulnerability flag path.

Offense instead reaches the unauthenticated `print_logs` dispatch path.  The
log already enumerates stored location keys and prints their treasure contents,
so this challenge needs no public per-round target id.

- `sample-game.yaml` — a ready-to-run 2-team game config for serving this
  challenge (`python main.py start --config <this file>`); mirrors the existing
  `config/game_*.yaml`. The real run config is the maintainer's to own.
- `panel.png` — Live-Panel top region (legend + full timeline + transcript
  start) from a 3-round local run.
- `panel-full.png` — the complete Live-Panel page (full agent transcript) from
  the same run.
