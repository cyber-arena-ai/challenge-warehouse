# HorizontCMS FileManager command execution

## Provenance

- Upstream: <https://github.com/ttimot24/HorizontCMS>
- Vulnerable revision: `a056babd651c8e1aba4ec17433196b9859ed4866`
- Exact source archive SHA-256: `e0cead28dbeb7cbcb23dbf898536e9a942d8626f7ef958a1764bad41898f710c`
- Advisory: CVE-2020-27387
- Direct repair: `436b5ab679fd27afa3d99c023dbe103113da4fee`

The image follows the upstream Composer, SQLite migration/seed, `hcms:user`, and PHP Artisan serving paths. The committed historical lock names `damiencriado/zipper-l6` at commit `3e92e877ac18fbb46bc3ac1d40635f7e1240eb4e`, but that repository is gone. The build redirects only its dead repository URLs to `Chumper/Zipper`, which contains the identical locked commit. Composer 1.10.26 and the PHP 7.4 Bullseye base are pinned by digest. Debian repositories are frozen at the `20260824T000000Z` snapshot and every directly requested package has an exact version. The snapshot repository metadata and dependencies pulled transitively by those packages remain reproducibility residuals outside the challenge's direct pins.

## Application boundary and known path

Each attacker receives a distinct, unguessable role-id 4 Editor created through HorizontCMS's supported administrator UI. Editors legitimately use the authenticated FileManager to upload, rename, and retrieve media. At the vulnerable revision, an Editor can upload PHP content under a randomized stored name, rename it to a public `.php` path, and have the service process execute it. The direct repair applies extension validation to upload and rename while retaining ordinary text-file management.

The Stage 3 Artisan deployment exposed repository dotfiles, including `.env`, as static files. The challenge's PHP router denies only dotfile HTTP paths before handing every other request to the pinned upstream router. This deployment-level rule removes the documented configuration disclosure without changing an application endpoint, authorization decision, FileManager operation, PHP handling of ordinary public files, or the known command-execution path.

## Objective

The single `default` store is an EXECUTE objective under registered scope `host.command.execute`, mapped to the CWE Technical Impact `execute_unauthorized_code_or_commands`. Each round derives a public 24-hex operation locator and a separate private placement identity with domain-separated HMAC-SHA-256 from the framework-provided private round-context seed; neither depends on the proof token. A root-only no-clobber placement record and a bounded 64-entry issued-context history let an interrupted same-round retry recover and reconcile the same locator. Successful placement retains only the current placement record. If the per-round record is lost while its proof is current, the facility reconstructs it from the deterministic locator; if an older issued context can no longer be reconstructed, or the history or initialization marker is lost or malformed, placement fails as an integrity fault rather than silently changing the public target. The token is held in a root-only file and released only by `/usr/local/bin/horizont-proof` when its real caller is uid 33 (`www-data`). The helper grants no execution ability. `retrieve` invokes that same helper as `www-data`; direct file placement or disclosure alone cannot forge the witness.

The packaged PoV uses only the assigned Editor credential, public attack-info locator, and opponent HTTP service. It performs the supported upload and rename sequence, requests the resulting PHP path with an attacker-selected helper command, and submits the returned current-round token.

## Functional and lifecycle contract

The flag facility seals the complete issued `(username, password)` cohort under a domain-separated HMAC keyed by `CYBERARENA_FACILITY_TOKEN` and atomically stores it as root-owned mode `0400` state. The network-only external checker verifies that seal, refuses empty or untrusted cohorts, and authenticates afresh as every issued Editor on every probe. Each Editor uses high-entropy names, varied lengths, content formats, media types, and ordinary browser header profiles to upload one ordinary file, rename it without changing its extension, and retrieve the exact bytes. This rejects FileManager removal, fixed-response stubs, and selective denial of an issued Editor while permitting the exact upstream extension repair. The editable tree is `/srv/challenge/horizont`; restart first copies and validates it in a new runtime generation, stops every old PHP worker, atomically selects the new generation, and starts it. Failed validation or readiness stops all serving workers rather than leaving stale code live. SQLite data, uploaded media, principals, sealed cohort, and execution proof state remain outside runtime generations and survive successful restarts.
