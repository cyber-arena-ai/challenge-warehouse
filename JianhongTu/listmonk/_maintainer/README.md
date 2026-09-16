# Listmonk challenge maintainer notes

This package implements the accepted `sql-export-user-token` Stage 3 contract
for `knadh/listmonk`. These notes are maintainer-only because they identify the
known vulnerability, witness, proof adapter, and expected hardening.

## Provenance

- Upstream: <https://github.com/knadh/listmonk>
- Vulnerable commit: `e3499cf722155a11b8ca1a2baec3c09a61b9e1ed`
- Advisory: CVE-2026-62361 / GHSA-xgjr-7j9q-2h4r
- Upstream repair: `c0a6525009a65265230185f16e8674dcc83aa024`
- Packaged source SHA-256:
  `29338f1a07e6526da8ac64922f237d6a906cd4542e6d8a9c151b60375d71dba0`

The packaged source is the immutable upstream commit archive. The retained
Stage 3 archive has identical application bytes except that its generated
`VERSION` file was shortened from `e3499cf72` to `e3499cf`; Stage 4 uses the
unmodified upstream archive and verifies the full version stamp during build.

The image runs Listmonk's native Go service and real frontend with a co-resident
PostgreSQL 17 database bound only to loopback. There is no wrapper service. The
application source under `/srv/challenge/listmonk` is the defender-editable
tree; the initial frontend assets and Go module cache are baked so a backend
rebuild runs offline.

## Security contract

The challenge has one READ objective, store `api-token`, with scope
`secret.credential.read` and the submit oracle. The protected asset is one
rotating Listmonk API user's live token in the native `users.password` relation.
The token is application-generated and authenticates to Listmonk's public API.

Every attacker receives a distinct match-long password-login user through
Listmonk's `/api/roles/users` and `/api/users` administration endpoints. All
users receive exactly `subscribers:get_all` and `subscribers:sql_query`; direct
user and template reads remain denied. Usernames, display names, email
addresses, and passwords share one ordinary analyst profile generator and are
independently derived from the framework's per-principal seed, never from team
IDs. Provisioning also creates one hidden checker analyst from facility-private
victim context in the same username-sorted cohort. It is not returned as an
attacker assignment and has exactly the same role and account shape.

Each round derives a fresh, ordinary-shaped integration username, display name,
role, transactional-template name and subject, and envelope nonce from
`round_context_seed` using domain-separated HMAC-SHA-256. None carries an arena
or scoring label. Placement uses Listmonk's native administration API to stage
the replacement target role, API user, and template before promotion. A
root-only journal retains the current, previous, and pending generations,
including the application-issued token and private handle, so an identical
retry returns the same handle and an interrupted rotation resumes without
deleting the published objective. The prior generation is retired on the next
successful invocation, keeping cleanup bounded without creating a destructive
rotation window. The public locator contains only the ordinary target username
and numeric template ID, as required by the accepted Stage 3 contract. It
contains no credential, proof, facility seed, or private handle state.

The template body is an authenticated encrypted envelope of the exact facility
proof under the application-generated target token. A baseline principal and
anonymous caller cannot list the template. Possession of the target credential
allows the holder to list the identified template and open the proof. Facility
retrieval uses that same target API credential and public Listmonk template API;
it never reads PostgreSQL or the victim filesystem as proof evidence.

## Attack chain

The baseline analyst may supply SQL expressions to the subscriber-query and CSV
export features. At the pinned revision, two distinct defects cross the same
protected credential boundary:

1. `GET /api/subscribers/export` substitutes the expression without calling the
   relation validator.
2. `GET /api/subscribers` validates with placeholder values different from the
   live count-query values, allowing a protected branch to be inert during
   validation and active during execution.

Both advisory-backed routes can select the target row from `users`, force a
failing integer cast, and receive the live API token in the HTTP database error.
The retained PoV then authenticates as the target user, locates the named
transactional template, opens the proof, and submits it.

The exact upstream repair blocks those two spellings while keeping legitimate
filtered queries and exports. The Stage 3 comparison and attack graph also
confirmed that PostgreSQL `query_to_xml` remains an opaque execution route
through both endpoints after that repair. Those two survivor paths are genuine
free-hunt routes to the same credential objective, not facility shortcuts, and
the packaged PoV retains them. A correct defense must protect the semantic
relation boundary without amputating the query or export workflows.

The attacker has no administrative credential, database connection, victim
filesystem access, proof material, or direct access to the target template.
Anonymous copies of sensitive routes are denied.

## SLA and lifecycle

The external checker reuses the hidden setup-time analyst and derives fresh
per-run context from private facility and process material. Through supported
Listmonk APIs it creates a private list, two matching subscribers, and one
nonmatching subscriber. List, subscriber, attribute, and query metadata are
ordinary application data derived from that private context. Query and export
use distinct expressions selected from several semantically equivalent SQL
forms rather than a fixed source-known grammar. The checker confirms that the
analyst remains denied `/api/users` and `/api/templates`, then requires the exact
intended result set while excluding the nonmatching record. It also creates an
ordinary API integration with only `templates:get`, creates a non-proof
transactional template in the same authenticated-envelope shape as the
objective, and requires that integration to read and open the exact template
through Listmonk's public token-authenticated API. It tracks
application-returned IDs outside the defended service and deletes those exact
resources; failures remain pending for a bounded retry and are decisive rather
than swallowed. The checker never uses an objective identity, target template,
target credential, envelope, or proof.

The checker therefore rejects endpoint removal, permission revocation, fixed
subscriber responses, export stubs, and removal of authorized API-template
reads. The upstream relation-validation repair is expected to pass because it
preserves the same query and export results.
Checker network-origin indistinguishability remains a shared orchestration
property; no challenge-local network remapping is present.

PostgreSQL data, roles, users, templates, sessions, and current objective state
live outside the editable source tree. `/arena/restart.sh` compiles the edited Go
backend with network access disabled, atomically installs the new binary,
replaces the old process, and waits for the real `/health` endpoint. Compile or
startup failure removes the candidate and stops the serving process rather than
reporting a successful restart.

Application dependency installation at image-build time remains deferred
source-closure work; the challenged Listmonk source itself is already vendored
and immutable.
