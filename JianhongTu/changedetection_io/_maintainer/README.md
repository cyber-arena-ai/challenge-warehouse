# changedetection.io Stage 4 provenance

Private implementation evidence; this file is not rendered to players.

- Upstream: `dgtlmoon/changedetection.io`
- Vulnerable commit: `1d7d812eb0faab37042246e2fbce04f29bb1b3aa`
- Repair commit: `417d57e5749441e4be9acc4010369bded805d66f`
- Source archive SHA-256: `1ee28dcf40c51857e1ab8ee07839d5512f0cdcb119f4aa25f8d58c966aaa4ba2`
- Resolved dependency manifest SHA-256: `14f17348dee1b72d3ee88165257f115f908a055c94ac6b3098df636beb22b49a`
- Accepted Stage 3 study: `xpath-file-read`

The one scored READ object is the application's native session-signing
credential, created as `/datastore/secret.txt` on first boot and loaded by
changedetection.io as its Flask secret. Current orchestration supplies the
scoreable proof. The trusted facility writes through the already-open native
file descriptor, renames that same inode to a round-derived
`/datastore/secret-<id>.txt`, and leaves `secret.txt` as the compatibility link
used by the unchanged application. The published target and PoV address the
rotating concrete path. Repeated same-round placement converges on the same
path; later placement moves the same native object, retires old target paths,
and preserves its type, mode, UID, GID, and application consumer. A failed
restart restores the prior bytes, path, link, and serving state.

This direct Docker-exec placement is necessary because exact-source search
found no supported application operation for rotating the Flask signing key.
It creates no application route, consumer, authorization boundary,
vulnerability, or attack path. It does expose a contract conflict: normative
FAC-1 requires non-execute placement through an application access layer,
whereas the maintainer-approved migration policy permits a justified
Docker-exec exception when no faithful application operation exists. This
package relies on that explicit exception; the shared documents still need a
single reconciled rule.

The network checker creates an anonymous watch against one of several ordinary
page shapes and benign native XPath selectors. Each run temporarily serves its
fresh page from the health poller's non-loopback address using a variable,
human-shaped URL and value, validates the public preview and exact source URL,
then deletes only the watch it created and stops the source server. This bounds
checker state without leaving publicly mutable health noise or admitting the
previous loopback-plus-64-hex selective-service shortcut. Restart persistence
is exercised separately by the lifecycle controls.

Source/dependency closure remains deferred by the migration contract. The
bundle nonetheless uses the exact accepted Stage 3 source archive and resolved
manifest and verifies the source archive digest during the image build.

The retained Stage 4 controls reproduce same-round placement convergence,
cross-round concrete-target rotation, the positive workflow, restart
persistence, feature-amputation, loopback/64-hex selective-service and canned
response rejection, and accepted upstream repair.
