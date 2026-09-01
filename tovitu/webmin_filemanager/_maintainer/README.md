# Webmin File Manager authoring notes

This package pins Webmin core `b374ad7d281a84f644c8ccace063c58793540cc6`
and Authentic Theme `d9b774412239092b2539a713327edda092d85f56` from
the accepted Stage 3 bundle. The image archive hashes are asserted in both the
Dockerfile and focused contract tests.

Canonical provenance:

- Webmin upstream: https://github.com/webmin/webmin
- Authentic Theme upstream: https://github.com/webmin/authentic-theme
- Advisory: https://github.com/CVEProject/cvelistV5/blob/main/cves/2022/0xxx/CVE-2022-0824.json
- Webmin repair: https://github.com/webmin/webmin/commit/39ea464f0c40b325decd6a5bfb7833fa4a142e38
- Authentic Theme repair: https://github.com/webmin/authentic-theme/commit/1c25cc9c37d011c62eb0de85d471ad353f6719b3

The `default` flag store is Tier 3 with scope `host.command.execute`. Its proof
requirement is execution of the current public release helper in Webmin's root
service context: the helper must retrieve the fresh round value from the
root-only in-memory broker. Reading or replacing the token-free helper does not
satisfy that requirement.

The baseline principal is a fresh Webmin user with exactly the `change-user`
module. Webmin's own ACL denies that user `/filemin/` and `/shell/`. The selected
theme revision nevertheless accepts the same session at its File Manager
extension, allowing remote download and chmod in the root-running service tree.
The maintained PoV uses that native workflow to publish a nonce-named CGI which
invokes the current root-only release helper and returns its output over MiniServ.
The helper path is an independently random, rotating public target. It contains
only a locator and connects to a root-owned Unix-socket broker; the current proof
exists only in the broker's memory, so File Manager download/archive operations
can expose the helper code but not the proof it releases when executed.

The external checker performs only Webmin HTTP operations. Before round 0, the
flag facility derives two restricted checker users and one File Manager user
from the facility secret and victim identity, then creates them through Webmin's
native ACL endpoint. The health facility independently derives the same private
credentials. They are not returned through attack-info or read from production.
Checker usernames and passwords have the same shape as issued Webmin users, and
its randomized File Manager artifacts and browser-like requests do not carry a
health-check label or arena-specific user agent.

The application tree at `/srv/challenge/webmin` is the only defender-editable
source. `/etc/webmin`, `/var/webmin`, the private bootstrap administrator
credential, and root-owned release broker remain outside that tree. The broker's
0600 socket is under `/run/webmin-arena`; it accepts only root peers and stores no
proof on disk. `/arena/restart.sh` ensures the broker is available, syntax-checks
the relevant Perl entrypoints, and replaces MiniServ without restarting the live
broker or reinitializing users, preferences, or configuration.

The coordinated repair added module validation and Webmin's native foreign
module security check in `authentic-theme/extensions/file-manager/file-manager-lib.pl`. A valid
defense preserves the administrator's dynamic File Manager download/retrieval
while keeping restricted users confined to `change-user`. Disabling the File
Manager or returning canned health responses is not valid.

Run the canonical gates from the locked orchestrator checkout with
`CYBERARENA_CHALLENGE_WAREHOUSE` pointing at this warehouse worktree. The
attacker-container PoV is `_exploit.py`; it discovers the current opponent,
principal, and locator through attack-info rather than using fixed match data.
