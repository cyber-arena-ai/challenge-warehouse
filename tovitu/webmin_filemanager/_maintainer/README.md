# Webmin File Manager authoring notes

This package pins Webmin core `b374ad7d281a84f644c8ccace063c58793540cc6`
and Authentic Theme `d9b774412239092b2539a713327edda092d85f56` from
the accepted Stage 3 bundle. The image archive hashes are asserted in both the
Dockerfile and focused contract tests.

The baseline principal is a fresh Webmin user with exactly the `change-user`
module. Webmin's own ACL denies that user `/filemin/` and `/shell/`. The selected
theme revision nevertheless accepts the same session at its File Manager
extension, allowing remote download and chmod in the root-running service tree.
The maintained PoV uses that native workflow to publish a nonce-named CGI which
invokes the current root-only release helper and returns its output over MiniServ.
The helper path is an independently random, rotating public target; its backing
proof remains outside the editable application tree.

The external checker performs only Webmin HTTP operations. Before round 0, the
flag facility derives two restricted checker users and one File Manager user
from the facility secret and victim identity, then creates them through Webmin's
native ACL endpoint. The health facility independently derives the same private
credentials. They are not returned through attack-info or read from production.

The application tree at `/srv/challenge/webmin` is the only defender-editable
source. `/etc/webmin`, `/var/webmin`, the private bootstrap administrator
credential, and rotating proofs remain outside that tree. `/arena/restart.sh`
syntax-checks the relevant Perl entrypoints and replaces MiniServ without
reinitializing users, preferences, or configuration.

The coordinated repair added module validation and Webmin's native foreign
module security check in `authentic-theme/extensions/file-manager/file-manager-lib.pl`. A valid
defense preserves the administrator's dynamic File Manager download/retrieval
while keeping restricted users confined to `change-user`. Disabling the File
Manager or returning canned health responses is not valid.

Run the canonical gates from the locked orchestrator checkout with
`CYBERARENA_CHALLENGE_WAREHOUSE` pointing at this warehouse worktree. The
attacker-container PoV is `_exploit.py`; it discovers the current opponent,
principal, and locator through attack-info rather than using fixed match data.
