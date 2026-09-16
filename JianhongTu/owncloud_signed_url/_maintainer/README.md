# Maintainer notes

- Upstream: <https://github.com/owncloud/core>
- Vulnerable commit: `ac4f3383952837bc6d260408d2db6d107a47c42c`
- Direct repair: `5019c53e3b79d9bf9a1f82563ea6315c909cd2bd`
- Advisory: CVE-2023-49105
- Base image: `owncloud/server@sha256:5f1c448cfb583552bfb6f36e9a343abb16c66211e66fc5db34462239cc932416`
- Vulnerable source archive SHA-256: `6f32e257e26dbe565313c285a0b82f0ad4c8a0d7d9e461e71c2ab97dfba68fba`
- Runtime asset archive SHA-256: `0d2c2598919b946eb5e60f1d14c9459bf4c4c65f7557e3895eb6ce1f706981fa`
- Ubuntu archive snapshot: `20230906T120000Z`
- Direct challenge package pin: `openssh-server=1:8.2p1-4ubuntu0.9`

The base image is immutable, and the one package added by this challenge comes
from a timestamped Ubuntu snapshot at an exact version. Its transitive packages
are bounded by that snapshot and the base image but are not each asserted with a
separate version in the Dockerfile.

The repair rejects signed requests for users whose signing key has not been
initialized. The challenge keeps the application-owned boundary from the Stage
3 study: an ordinary target user has no initialized key, and an attacker who
knows only that user's public name and current DAV path must not be able to read
or overwrite the file. The service's ordinary account, WebDAV, initialized
signed-URL, persistence, and source-reload workflows remain required.

Only the advisory-backed private-file read is a scored objective. The reproduced
signed PUT remains historical vulnerability and free-hunt evidence; only
cross-boundary reading is measured.

Before any WebDAV mutation, planting atomically preallocates a fresh
ordinary-shaped victim identity, its private password, and one ordinary
document locator in root-only match-local state. The public identity, locator,
and private placement key are independently HMAC-derived from Orche's private
`round_context_seed`; the proof value is not context entropy. Only the victim
identity and locator leave the private helper. A repeated placement, including
from a fresh handler, recovers the same identity and locator, while a new round
seed produces a fresh target. A root-only issuance marker makes missing state
for an already-issued tuple fail before any WebDAV mutation, and corrupt stored
state also fails closed.

Principal provisioning seals the complete issued `(username, password)` cohort
under an HMAC keyed by `CYBERARENA_FACILITY_TOKEN` and atomically stores the
payload and tag as a root-owned mode-0400 file. The checker reads that opaque
state through the facility exec bridge, verifies the seal outside the prod
trust boundary, rejects an empty or substituted cohort, and authenticates
afresh as every issued participant on every probe. Each participant exercises
fresh ordinary DAV PUT/GET, peer isolation, and initialized signed-URL behavior
through only `target.host` and the declared service port. A six-member
facility-derived pool remains available only to supply the isolation peer when
the match has a single opposing participant; it no longer stands in for issued
participants. The seal is a known-message tag under the facility token, the
accepted in-package binding tradeoff pending a dedicated framework transport
for issued assignments.

The checker independently omits or fills each optional request header using its
ordinary grammar: user-agent products, media ranges, language ranges, encoding
lists, and connection preferences. Half the user-agent products are ordinary
client names and half are free-form tokens over the RFC 9110 token alphabet, so
no product table admits every health request; the connection preference is
close, keep-alive, or absent, covering what ordinary clients send. Numeric
versions, optional ordinary user-agent comments, and shuffled media ranges
prevent a fixed supported-profile prefix. The comment carries no per-request
marker: an ordinary client emits none, so one would identify health. Each
request generates a case-varied exact,
subtype-wildcard, or global-wildcard range for its expected representation with
an optional strictly positive quality, then shuffles that range among optional
values. Encoding lists vary only among identity, gzip, and deflate, which the
checker consumes. This represents the declared participant workflow without
advertising browser-only encodings the checker cannot decode. Values stay at
ordinary bounded lengths; they do not attempt exhaustive HTTP grammar or
server-limit coverage beyond the declared ownCloud workflow.

The `arena_agent` account owns the editable source, while Apache can only read
it. The editable source is not the served document root: startup and restart
copy it into a root-owned runtime generation while keeping ownCloud's official
`/mnt/data` config, apps, users, and files persistent. Restart syntax-checks
every PHP file that the pinned PHP 7.4 runtime can parse before stopping Apache.
Ten bundled PHP-8-only compatibility files are excluded from PHP 7.4 lint but
must either match their pinned SHA-256 digests or, when edited, pass PHP 7.4
lint. Restart atomically selects the candidate and records it as last-good only
after HTTP readiness. Any validation, stop, start, or readiness failure removes
readiness and stops Apache, so neither stale workers nor a failed candidate keep
serving. A successful restart removes obsolete candidate generations while
retaining the active generation and immutable initial baseline.
Initial bootstrap temporarily retains ownCloud's required write access to its
generated `.htaccess`; a pre-server hook re-locks the complete generation before
Apache starts.
