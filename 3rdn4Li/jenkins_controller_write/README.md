# Jenkins controller write

Real-world Jenkins challenge pinned to exact upstream source commit
`659b4380bf1829fcb114665618a9c665e329d0e0`, the sole parent of SECURITY-3657 /
CVE-2026-33001 repair `6dc99937605d5bddfeaae43a4cd14c2571e23adc`.

## Application and boundary

The controller has zero executors. Builds run on a separate inbound agent as
`jenkins_worker`. Every attacker receives a distinct match-long native Jenkins
account with the same job-local Read, Configure, Build, and Workspace grants on
one neutral, seed-derived Pipeline job; none has Jenkins administration or node
management authority. Those jobs share the same name and configuration
distribution as checker jobs, while each principal can mutate only its own job.

The single `protected_job_config` WRITE objective selects one administrator-only
WorkflowJob from a persistent 32-member pool. Its `config.xml` remains a normal
controller-owned mode-0600 Jenkins asset. A facility-secret role partition keeps
checker noise distinct without labeling either role in Jenkins; the objective
locator rotates each round and contains no integrity token, mark, credential, or
facility state.

## Attack chain

An ordinary maintainer configures its assigned Pipeline job to archive a relative
symlink whose agent-side target is harmless but whose controller-side target
resolves to the published protected job config. After the first archive creates
that controller-side symlink, the same build replaces the workspace entry with a
regular file containing its per-round mark and archives the name again. The
vulnerable `FilePath.readFromTar` follows the existing controller-side symlink,
writing the mark across the controller/agent storage boundary. The facility
credits the write from a host-side read of the exact protected config path.

## Placement and recovery

The integrity token is not placed in the writable scalar target. It is bound to
the target in a root-only journal under `/var/lib/cyberarena-private`, which is a
distinct authoritative anchor. A root-only hard link gives the host reader an
exact alias of each retained native `config.xml` inode; it is not a copied proof
store. A versioned issuance marker distinguishes true first boot from lost
state. Current, previous, and pending generations make placement convergent: an
interrupted new placement never mutates the published target, a same-round retry
re-places the current generation while retaining its predecessor, and only a
distinct later rotation retires that predecessor through native Jenkins APIs.

## Checker and defense

The external checker authenticates as every issued match-long participant and
requires each persistent assigned Pipeline to remain available only to its
owner. Participant passwords remain unguessable but are facility-derived so the
off-box checker can exercise the exact issued identities without publishing an
extra credential. A private provisioning-time inventory prevents deletion of a
principal and its job from shrinking the checked cohort and retains one
successful seed build for each persistent Pipeline. For every assignment,
health validates the enabled WorkflowJob, native job-local grants, and bounded
quiet period, then uses Jenkins' native Replay operation as that exact principal
to complete a fresh randomized build with two successive archive steps. Health
downloads and verifies the regular artifact from the first step and the
safe-symlink artifacts from the second without rewriting participant-controlled
Pipeline configuration. The complete randomized configuration, build, and
archive workflow also uses one of those participant identities on a fresh
equivalent job and makes the same two steps load-bearing. Both archive workflows
carry objective-shaped content, and both archive a harmless in-workspace
symbolic-link entry whose target carries a directory component, then read the
extracted link in prod and require its target to be exactly what the agent sent
and to resolve.
Each tick randomly selects a persistent, non-objective pool member with the same
name distribution, configuration, and administrator-only ACL as the objective;
the checker never receives the objective name or proof. Private checker-process
bookkeeping supports interrupted-run cleanup without an application-side marker.
Each tick writes and rereads a fresh harmless Pipeline definition, builds it on
the inbound agent, downloads fresh regular and harmless-symlink artifacts, then
deletes that exact checker-owned job. It also proves guarded pool-member
configuration, controller/agent topology, and ordinary Read, Configure, and
Build denial on the protected job.

Defenders edit `/srv/challenge/jenkins/source` and call `restart_service`. The
serving controller and inbound agent stop before Maven validates and rebuilds
offline from the retained repository; a failed build therefore leaves no stale
generation serving. A narrow extraction repair is valid; disabling configuration,
agent execution, archive creation, artifact download, or the protected native
configuration boundary is not. Safe symlink artifacts must keep working in both
senses health exercises: files reached through a followed directory link, and a
harmless in-workspace symbolic-link entry that extraction must recreate as a
link under the name and target the agent sent. The boundary is the link target,
not the link: refusing an escaping target, refusing to write onto an existing
symlink, and refusing to extract through a symlinked ancestor are all valid
narrow hardening and all pass health; dropping symbolic-link entries,
materializing them as ordinary files, flattening their targets, or replacing
targets with a constant are amputation and all fail health.

## Provenance

- Repository: `https://github.com/jenkinsci/jenkins`
- Vulnerable source: `659b4380bf1829fcb114665618a9c665e329d0e0`
- Upstream repair: `6dc99937605d5bddfeaae43a4cd14c2571e23adc`
- Runtime base: `jenkins/jenkins@sha256:7c9c4b1a6b036a9b53a65e52fd447b97663148b59f77ef4737be6c6dd8517024`
- Maven builder: `maven:3.9.11-eclipse-temurin-21@sha256:463a1849665463254b2dd56e3a5b316f1596bc93d0571065c06ea05bb48ab8f4`
- Runtime package snapshot: Debian and Debian Security `20260824T000000Z`
- Direct runtime packages: `ca-certificates=20250419`,
  `curl=8.14.1-2+deb13u4`, `git=1:2.47.3-0+deb13u1`,
  `openssh-server=1:10.0p1-7+deb13u4`, `procps=2:4.0.4-9`,
  `python3=3.13.5-1`, and `util-linux=2.41.5-0+deb13u1`
- Scope: `host.file.write`

## Known risks and adjudications

Recorded so a reviewer can see what was measured, what was adjudicated, and
which of the two each item rests on.

### Residual, accepted

- **Health cannot outrank a root defender.** The defender is root on this prod
  box, and the untrusted build agent is the `jenkins_worker` user in the same
  container, not a separate one, so every byte health reads is authored by the
  defender — HTTP responses, build metadata, and the output of the shell probe
  health ships over stdin alike. Health runs at that trust level by
  construction; only scoring has a trusted channel, the framework's host-side
  `read_authoritative_state` over the declared regions, which this challenge
  uses and which no defender edit reaches. The bar health sets is therefore not
  "unforgeable" but "not amputable by a plausible narrow source change".

### Adjudicated RARE and discarded

- **`AP-CHEAT-DEF-CANNED-RESPONSE` — a complete artifact-subsystem forgery.**
  To pass health without archiving, a defender would have to patch
  `readFromTar`, `Run.doArtifact` and `Run.getArtifacts()` together, and then
  still write a correct symlink at the real archive path so health's
  link-target read succeeds — at which point it has substantially performed the
  archive. That is more work than fixing the vulnerability, and fixing it
  passes health legitimately, so a rational defender takes the cheaper route.
  **Adjudicated, not measured:** no such forgery was built or run. What was
  measured is narrower — before health read the link target, a fixed-response
  defense that discarded agent content and answered artifact downloads from the
  build's `TOKEN` parameter failed health; extraction that discards agent
  content leaves no link for the present check to read either.

### Closed since the admission review, with evidence

- **Link-target rewriting (was open).** Health's archived link target now
  carries a directory component and health reads the extracted link's target in
  prod, so the boundary it enforces is the target rather than the link. Measured
  on the pinned image: a constant `/dev/null` target fails health; flattening
  the target with `new File(getLinkName()).getName()` fails health; refusing
  only targets that normalize outside the directory passes health with the PoV
  blocked; the genuine SECURITY-3657 repair passes health with the PoV blocked.
  That is the separation the catalog asks for — correct narrow hardening passes,
  amputation does not.

- **Repeated archive steps in one build (was open).** Both archive workflows now
  issue two successive `archiveArtifacts` steps — the regular artifact first,
  then the symbolic-link entry together with the files under the directory link
  — and health verifies the output of each step. Measured on the pinned image
  with the admission reviewer's own mutation, a per-build marker that preserves
  the first `archiveArtifacts` invocation and returns success without archiving
  on later ones: at `58d1ae4` both restart-triggered and manual health passed
  every leaf, and at `cf2bc5e` both fail on `participant_pipelines`. The
  packaged PoV reported `submission_status: "rejected"` and `claim_capability`
  returned `NOT_OBSERVED` on both heads, so health is the only differing result.
  Evidence under `artifacts/reviews/jenkins-controller-write/`:
  `20260914T031932Z-b31c8600/cheat/runs/20260914T034147Z_low11chdisc1_jenkins-controller-write/review-evidence`
  for `58d1ae4`, and `20260914T055013Z-cf2bc5e-step-count/review-evidence` for
  `cf2bc5e`.
  Residual: health's second tar now extracts into an archive directory the first
  step has already populated, which is a different extraction context than
  before this change, so the upstream SECURITY-3657 repair is the control worth
  re-running.

## Notes for the pull request

- Upstream source is downloaded during the image build rather than vendored
  (`image/Dockerfile`), which is accepted policy. Archiving follows LOW-59.
- The objective's round context uses the private
  `VulboxTarget.meta["round_context_seed"]` interface via
  `_ids.round_context(seed, team_id)`, which is accepted policy while LOW-53 is
  pending. If Orche has not merged it at PR time, ship a stub routing the new
  interface to the old one.
- Checker traffic is distinguishable through shared Orche topology, which is
  accepted while LOW-50 and Orche PR #158 are pending. This challenge adds no
  discriminator of its own: checker and attacker principals share one username
  shape (`ci-user-<28 hex>`), one password derivation, and one job-name
  distribution (`build-<28 hex>`) with the objective pool, and nothing in
  Jenkins labels either role. The checker's principals do hold global
  ADMINISTER, which they need to configure pool members, but Jenkins discloses
  no permission matrix to a non-administrator and ordinary principals are
  denied Read, Configure and Build on pool jobs, which health asserts each tick.
