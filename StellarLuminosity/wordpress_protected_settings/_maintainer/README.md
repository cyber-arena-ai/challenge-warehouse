# WordPress protected-setting challenge

This package pins `wordpress/wordpress-develop` at
`3d199988d6e0e011b0a71c4c58b900cd475dc73d`, the sole parent of upstream repair
`6f2074dda61864a03f334d70414d1690ce7e5c79`. The accepted Stage 3 study is
`artifacts/projects/WORDPRESS__WORDPRESS_DEVELOP/stage3/wp2shell-chain/`.

The advisory-backed anonymous HTTP path combines CVE-2026-63030 and
CVE-2026-60137. A malformed REST batch path shortens the route-match array,
then later requests are dispatched through the wrong handler. A nested carrier
reaches `WP_Query` with an unnormalized scalar `author__not_in`, producing a
blind SQL oracle over application data. The grouped repair preserves match
indexes, prevents nested top-level REST dispatch cycles, and normalizes the
author exclusion list.

## Challenge contract

- Baseline principal: anonymous HTTP client; WordPress exposes no account for
  this public surface and the challenge does not invent one.
- Objective: `protected-setting`, READ, `app.cross_boundary.read`.
- Target: a fresh `site_private_<random>` WordPress option derived with a
  domain-separated HMAC from the framework round-context seed.
- Boundary: WordPress site settings are application-owned guarded state; direct
  anonymous settings access is denied while public posts and batch requests
  remain available.
- Oracle: the facility plants the exact proof through WordPress's native
  `update_option()` application operation and later reads it through the same
  bootstrapped application API. The public locator is only the option name.
- PoV: `_exploit.py` fetches the current locator from attack-info, uses only
  anonymous HTTP traffic to reconstruct the option value, and submits it.

The graph's administrator-password-hash node is exploratory coverage rather
than the accepted Stage 3 objective. WordPress natively hashes passwords, so it
cannot store and return the framework's exact READ proof without bypassing the
application model. It is intentionally not registered or scored.

The full production source is editable at `/srv/challenge/wordpress`. The three
upstream repair-touched PHP files are linted before a complete source deploy;
MariaDB data and the current objective survive Apache replacement. Runtime auth
salts and the site-owner password rotate independently per container, so no
shared baked credential can be replayed against an opponent.

The network checker first uses the same anonymous authority as contestants.
Each probe gets two fresh facility-created public posts, checks exact direct
and filtered post semantics, submits fresh post and user mutations through
native batch dispatches, and rereads both posts to prove the application denied
the mutations without changing state. It then uses a fresh operation-scoped
native application password to require one successful objective-shaped author
batch update. Cleanup removes the posts and revokes that credential, and the
checker verifies the retired credential is rejected. It also checks native
protected-settings denial.

The two Debian stages use dated snapshots selected immediately before their
pinned base images were created, every explicitly installed OS package has an
exact version, and the WP-CLI 2.12.0 artifact is verified by SHA-256. Broader
dependency/source closure remains deferred by the migration contract.

The private Stage 4 `controls.py` artifact reproduces the positive workflow,
restart and credential controls, feature-amputation and canned-response
rejection, and acceptance of the grouped upstream repair.
