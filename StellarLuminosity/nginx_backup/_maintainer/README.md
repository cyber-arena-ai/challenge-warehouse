# Nginx UI management

## Provenance

- Upstream: [0xJacky/nginx-ui](https://github.com/0xJacky/nginx-ui)
- Vulnerable revision: [`2ae32f3be5fccaca013e14fef6e497acaaae21ba`](https://github.com/0xJacky/nginx-ui/commit/2ae32f3be5fccaca013e14fef6e497acaaae21ba)
- Exact repair: [`18538df8cba07646f3d506f82956217712882932`](https://github.com/0xJacky/nginx-ui/commit/18538df8cba07646f3d506f82956217712882932)
- Advisory: [CVE-2026-27944 / GHSA-g9w5-qffc-6762](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762)
- Retained source archive SHA-256: `a31f1da371af9e0aa5cd7cd4837da5f6e30a97f35e7baff8c800d3ea4d627d5b`

The vulnerable revision registers `GET /api/backup` without authentication.
The native backup includes the active `app.ini` and returns the AES key and IV
needed to decrypt it. The exact repair adds `AuthRequired` to backup export and
preserves authenticated export.

The build uses the official [Node](https://hub.docker.com/_/node) and
[Go](https://hub.docker.com/_/golang) images at OCI digests
`sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e`
and `sha256:f4490d7b261d73af4543c46ac6597d7d101b6e1755bcdd8c5159fda7046b6b3e`.
Its Debian 12 packages come from the immutable
[`20260824T000000Z` Debian snapshot](https://snapshot.debian.org/archive/debian/20260824T000000Z/)
and are installed at the exact versions declared in `image/Dockerfile`, including
Nginx `1.22.1-9+deb12u9` and OpenSSL `3.0.20-1~deb12u2`. The flag and health
facility setup scripts use the corresponding immutable Debian 13 snapshot and
OpenSSL `3.5.6-1~deb13u2` under the pinned orchestration facility base. The
upstream `pnpm-lock.yaml` locks every JavaScript resolution with an integrity
hash, the package-manager descriptor pins pnpm 10.28.2 by SHA-512, and `go.sum`
authenticates the version-pinned Go module graph. Those locks are populated at
image-build time and restart runs with Go's module proxy and checksum network
disabled. A fail-closed build adaptation changes only the native outer backup
member order, preserving its names and contents while placing the
objective-independent nginx configuration archive before the private Nginx UI
state archive. This lets the external checker validate ordinary backup framing
without exposing or decrypting objective material; restore behavior and the
vulnerable and repaired access boundaries are unchanged.

## Security model

The baseline is Nginx UI's genuine anonymous public HTTP surface; the challenge
does not provision attacker identities. The single `node-credential` READ store
has scope `secret.credential.read`. Its proof is the current round's exact flag,
installed as the application-native protected `[node] Secret`. The public
locator is a seed-derived rotating node name. The application itself accepts the
credential through `AuthRequired` using `X-Node-Secret`.

Placement uses a separate opaque administrator created once through Nginx UI's
native installation API. It logs in through the encrypted login flow, exports a
native backup, changes only the node name and secret in the nested configuration,
removes the database member, and restores only that configuration through the
native restore API. Concurrent database state and the administrator remain
intact. Retrieval is a pure application request authenticated with the expected
node credential; it does not read the container filesystem.

## SLA

The external checker uses the objective-independent bootstrap administrator to
create one ordinary randomized administrator for each run, then performs the
same complete workflow independently as the bootstrap administrator and the
fresh peer. For each principal it uses fresh encrypted login inputs, temporarily
changes that native user's language, reads the protected objective-free
server-name setting, then creates and reads a randomized nginx
configuration through the native API. An ordinary authenticated download is
consumed through its complete `hash_info.txt` and `nginx.zip` members in one
response. Their encryption, ZIP framing, CRCs, sizes, version, and same-response
nginx-content digest are validated; the nginx archive is decrypted and must
contain the exact randomized configuration body. Both authenticated downloads
retain the encrypted private member and bind its `database.db` to the fresh
peer's exact current user and language state. AES random-access decryption reads
only the nested central directory, member headers, and database member; it does
not decrypt the `app.ini` payload that contains the live node objective. The
same encrypted manifest and members are also submitted to the native restore
validator with both restore switches false and hash verification enabled, so
both manifest hashes are enforced without changing live state or restarting the
service. The complete outer central directory and end record must still describe
the exact three response members and offsets. Finally, the checker removes the
configuration, restores the preference, and deletes the temporary administrator.
Removing backup, returning a bodyless or truncated full download, amputating the
private member, substituting an incomplete prefix, serving canned data,
selectively serving one credential, or breaking settings/login fails; the exact
upstream repair passes because authenticated backup and restore validation remain
available.

## Attack chain

An anonymous caller requests `GET /api/backup`, reads `X-Backup-Security`,
decrypts `nginx-ui.zip`, and reads the node credential from `app.ini`. No host,
Docker, facility credential, victim filesystem, or expected proof participates
in the packaged PoV. The caller submits the recovered credential through the
ordinary read oracle.
