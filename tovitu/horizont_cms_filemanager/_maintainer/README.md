# HorizontCMS FileManager command execution

## Provenance

- Upstream: <https://github.com/ttimot24/HorizontCMS>
- Vulnerable revision: `a056babd651c8e1aba4ec17433196b9859ed4866`
- Exact source archive SHA-256: `e0cead28dbeb7cbcb23dbf898536e9a942d8626f7ef958a1764bad41898f710c`
- Advisory: CVE-2020-27387
- Direct repair: `436b5ab679fd27afa3d99c023dbe103113da4fee`

The image follows the upstream Composer, SQLite migration/seed, `hcms:user`, and PHP Artisan serving paths. The committed historical lock names `damiencriado/zipper-l6` at commit `3e92e877ac18fbb46bc3ac1d40635f7e1240eb4e`, but that repository is gone. The build redirects only its dead repository URLs to `Chumper/Zipper`, which contains the identical locked commit. Composer 1.10.26 and the PHP 7.4 Bullseye base are pinned by digest.

## Application boundary and known path

Each attacker receives a distinct, unguessable role-id 4 Editor created through HorizontCMS's supported administrator UI. Editors legitimately use the authenticated FileManager to upload, rename, and retrieve media. At the vulnerable revision, an Editor can upload PHP content under a randomized stored name, rename it to a public `.php` path, and have the service process execute it. The direct repair applies extension validation to upload and rename while retaining ordinary text-file management.

The Stage 3 Artisan deployment exposed repository dotfiles, including `.env`, as static files. The challenge's PHP router denies only dotfile HTTP paths before handing every other request to the pinned upstream router. This deployment-level rule removes the documented configuration disclosure without changing an application endpoint, authorization decision, FileManager operation, PHP handling of ordinary public files, or the known command-execution path.

## Objective

The single `default` store is an EXECUTE objective under registered scope `host.command.execute`, mapped to the CWE Technical Impact `execute_unauthorized_code_or_commands`. Each round rotates a public 24-hex operation locator and a separate proof token. The token is held in a root-only file and released only by `/usr/local/bin/horizont-proof` when its real caller is uid 33 (`www-data`). The helper grants no execution ability. `retrieve` invokes that same helper as `www-data`; direct file placement or disclosure alone cannot forge the witness.

The packaged PoV uses only the assigned Editor credential, public attack-info locator, and opponent HTTP service. It performs the supported upload and rename sequence, requests the resulting PHP path with an attacker-selected helper command, and submits the returned current-round token.

## Functional and lifecycle contract

The flag facility provisions two per-victim, equal-role checker Editors through the supported administrator workflow. Their identities are derived from facility-owned state that is never copied into production or exposed to attackers. The network-only external checker uses fresh inputs on every run: each Editor independently logs in, uploads unpredictable text, renames it to an unpredictable `.txt` name, and retrieves the exact bytes. This rejects FileManager removal and fixed-response stubs while permitting the exact upstream extension repair. The editable tree is `/srv/challenge/horizont`; restart validates application PHP, replaces the serving process, and preserves SQLite data, uploaded media, principals, and execution proof state.
