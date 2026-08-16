# changedetection.io authoring record

This challenge targets
[`CVE-2026-29039` / `GHSA-6fmw-82m7-jq6p`](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-6fmw-82m7-jq6p)
in [changedetection.io](https://github.com/dgtlmoon/changedetection.io) at
upstream commit
[`1d7d812eb0faab37042246e2fbce04f29bb1b3aa`](https://github.com/dgtlmoon/changedetection.io/commit/1d7d812eb0faab37042246e2fbce04f29bb1b3aa).
The upstream correction is
[`417d57e5749441e4be9acc4010369bded805d66f`](https://github.com/dgtlmoon/changedetection.io/commit/417d57e5749441e4be9acc4010369bded805d66f).
Stage 3 built both revisions and confirmed that an authenticated watch using
XPath `unparsed-text()` returns a mounted host file in normal watch history on
the former, while the exact fix rejects the expression and preserves benign
XPath selection.

## Intended capability and attack chain

The public operator token creates an ordinary watch with `POST /api/v1/watch`.
The requests fetcher retrieves a benign loopback fixture, a background worker
evaluates the operator-controlled XPath 3 expression in the application
process, and `GET /api/v1/watch/<uuid>/history/latest` returns the selected
content. A direct `file://` watch URL is rejected, so the XPath evaluator is the
required path.

The `default` store maps to Tier 1 scope `host.file.read`, anchored to CWE
Technical Impact `read_data`: recovering it proves that the remote operator
made the application return the contents of a private host file. The rotating
witness is the archive access token inside a
private operator report at
`/var/lib/changedetection/private/reports/<random>-operator-report.txt`. Both
the report identity and token rotate, and the file contains realistic report
metadata rather than a flag-only fixture. It is readable by the application
process and has no direct HTTP route. The privileged flag handler plants and
observes it out of band; the reference exploit retrieves it only through watch
processing and history. `flag_id()` publishes only the current report path as
the per-round attack locator; it never publishes the flag or a facility
credential.

The browser UI is protected by a random per-box password that is generated and
discarded during setup. The published operator API token is restored before
each service launch, preventing unauthenticated settings changes from rotating
the intended credential while keeping the authenticated watch API available.

## Feature-preservation gate

The external checker creates fresh, randomized watches over the authenticated
API. Benign watches before and after the host-access probes prove watch
creation, requests fetching, XPath selection, worker execution, persistence,
and history retrieval as one workflow. Public canaries then exercise
`unparsed-text`, `unparsed-text-lines`, `unparsed-text-available`, `doc`,
`doc-available`, `environment-variable`, and
`available-environment-variables`. Each probe may remain available or be
terminally rejected without depending on one error message or requiring the
file and environment families to share a defense. These probes never touch the
flag or its path.

This gate does not prove execution integrity against a root defender or make an
adversarial review unnecessary. It is intended to reject obvious XPath feature
amputation while allowing equivalent narrow hardening without requiring the
upstream parser implementation or its complete blocklist.

## Reproducibility

The image fetches and verifies the exact upstream commit during build. Its
linux/amd64 Python base is pinned to immutable manifest digest
`sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15`.
Runtime system packages are resolved from Debian snapshot
`20260715T000000Z`.
`image/requirements.lock` records the full dependency resolution from the Stage
3 vulnerable image (`sha256:080867d4fa97...`) and installs it with `--no-deps`.
Runtime fetches are not needed. The defender edits
`/srv/challenge/changedetection`; restart compiles the Python tree, relaunches
the service, and preserves the datastore and planted report.

Practical acceptance is: baseline checker green and reference exploit recovers
the exact planted flag; after applying upstream commit `417d57e...`, the checker
remains green, all seven host-access probes classify as blocked, and the exploit
does not recover the flag.
