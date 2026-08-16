# etcd nested-transaction RBAC challenge

## Source and service

- Discovery source: the retained OSV snapshot, component
  [`CVE-2026-33343` / `GHSA-rfx7-8w68-q57q`](https://github.com/etcd-io/etcd/security/advisories/GHSA-rfx7-8w68-q57q).
- Upstream: <https://github.com/etcd-io/etcd>, 52,012 GitHub stars in the
  retained 2026-08 source catalog.
- Service: etcd's networked v3 key-value API with built-in users, roles, and
  key-range permissions. This model applies to applications that expose etcd
  directly to partially trusted clients; typical Kubernetes deployments use
  Kubernetes authorization instead and are not the target scenario.
- Exact vulnerable revision:
  `c22bcad7820f81ff1c143d87e7b7e8724c637f71`, the first parent immediately
  before the release-3.4 recursive transaction-authorization merge.

## Vulnerability and patch

`checkTxnReqsPermission` authorizes range, put, and delete operations present
directly in a transaction, but does not recurse into a nested `RequestTxn`.
Consequently, a role restricted to `/teams/analyst/` can place a range request
for `/services/` inside a nested transaction and read keys outside its grant.

The narrow upstream security merge
[`2dd439867e35e0ec13df4787f79b076ac00b68d7`](https://github.com/etcd-io/etcd/commit/2dd439867e35e0ec13df4787f79b076ac00b68d7) adds recursive
`checkTxnAuth` handling for `RequestTxn` and regression coverage for nested
read, write, and delete operations. OSV records the subsequent v3.4.42 release
bump `89dc59aa1c7cc458aae18876a4866d29600bc07a` as the formal fixed boundary;
the authoring baseline uses the true pre-security-merge parent above.

## Attack chain and checker contract

The attacker authenticates as the published `analyst` identity, whose normal
workflow supports reads, writes, deletes, and nested transactions only below
`/teams/analyst/`. A direct read of `/services/` is denied. The vulnerable path
is v3 authentication -> outer transaction -> nested transaction -> range read
-> protected key response.

The external checker uses randomized keys and values. It requires direct
out-of-range denial and a complete allowed-prefix workflow with direct write,
nested read plus write, readback, and cleanup. For a fresh protected canary it
accepts either exact vulnerable disclosure or permission denial, so both the
historical baseline and a recursive authorization repair pass; disabling
transactions, stubbing responses, removing authentication, or amputating
ordinary key operations fails.

## Flag and capability

The `default` store is Tier 1 scope `app.cross_boundary.read`, anchored to CWE
Technical Impact `read_data`. Each plant replaces the prior production-service
record with a fresh identity and stores the rotating flag as its database
credential at
`/services/production/<random-service-id>/credentials/database-password`. Recovering it
through the public v3 API proves `app.cross_boundary.read`, mapped to the MITRE
CWE Technical Impact `read_data`: an authenticated identity reads application
data beyond its key-range authorization boundary. The public flag-id is the
generated key path, never the flag value; retrieval rejects handles outside
that exact generated shape.

## Reproducibility

The image uses Go 1.26.1 on the immutable linux/amd64 base digest
`sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd`
and resolves runtime packages from Debian snapshot `20260715T000000Z`.
Application dependencies are fixed by the pinned upstream commit's `go.sum`;
the build copies that exact module cache into the runtime image so defender
restarts compile with `GOPROXY=off`, `GOSUMDB=off`, and `GOTOOLCHAIN=local`.
