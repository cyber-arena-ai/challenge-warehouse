# Maintainer helpers — NOT challenge artifacts

The files in this folder are **not** part of the challenge. They exist only to
make reviewing and running this PR easier and can be deleted after merge —
nothing in the challenge package imports them.

- `sample-game.yaml` — a ready-to-run 2-team game config for serving this
  challenge (`python main.py start --config <this file>`); mirrors the existing
  `config/game_*.yaml`. The real run config is the maintainer's to own.
- `panel.png` — Live-Panel top region (legend + full timeline + transcript
  start) from a 3-round local run.
- `panel-full.png` — the complete Live-Panel page (full agent transcript) from
  the same run.
