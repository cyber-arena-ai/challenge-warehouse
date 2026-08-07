# Jenkins controller write

Real-world Jenkins challenge pinned to 2.554, upstream tag commit
`6b3bf8967e1e26a2bee4f0c0823bc8bae69009bf`. CVE-2026-33001 was fixed by
upstream commit `6dc99937605d5bddfeaae43a4cd14c2571e23adc` and released in
2.555. The image pins the linux/amd64 manifests of both upstream images:

- 2.554: `sha256:7c9c4b1a6b036a9b53a65e52fd447b97663148b59f77ef4737be6c6dd8517024`
- 2.555: `sha256:9d084dc939ebd625f67e04520aefd1fb62e954e1fbd416e9d096b6e3a7196719`

## Intended path

The `player` account has Overall/Read and job-local Read, Configure, Build, and
Workspace permissions on `archive-lab`; it has no Administer or node-management
permission. The controller has zero executors. A separate inbound agent runs as
`jenkins_worker`.

The exploit archives an agent-side symlink whose target exists, replaces the
workspace entry with a regular file, then archives the same name again. Jenkins
2.554 follows the already-created controller-side artifact symlink on the
second extraction. The target is the pre-existing
`/var/jenkins_home/.ssh/authorized_keys`: its parent is searchable but the file
is neither readable nor writable by `jenkins_worker`. The attacker installs an
SSH key, logs in as the controller OS user, and reads the controller-owned flag.

The platform-required sshd is the restart-free receipt that turns the historic
controller file-write primitive into a scoreable network path. It does not give
the attacker an initial login; access is acquired only after the CVE succeeds.

## Defense and negative control

`/srv/challenge/jenkins/release` initially contains `2.554`. Changing it to
`2.555` and invoking `restart_service` selects the bundled upstream security
release without network access. Jobs, build history, and planted flags survive;
the restart also clears any previously installed Jenkins-user SSH key. The same
two-archive PoC then fails with:

```text
entry 'pivot' would write through existing symlink
```

Normal scoped configuration, inbound-agent builds, artifact archiving, and
artifact download continue to pass `/arena/checker.sh`.

## Why the health check asserts more than "the service answers"

Three cheap moves would otherwise neutralise the round without repairing the
extraction path, so each is now a health failure:

- **Amputating the attack surface.** `archive-lab` is the job a scoped
  maintainer configures and builds. Disabling it, turning its Groovy sandbox off
  (which parks every future build behind admin script approval the player can
  never obtain), or dropping a `player` grant from its authorization matrix all
  leave Jenkins answering normally. `checker.py:assert_attack_surface` reads the
  job's own `config.xml` and rejects each. A narrow fix to the controller-side
  extraction leaves all of them untouched.
- **Starving build capacity.** The maintainer may legitimately run builds, but a
  single `sh 'sleep 3000'` once held the only executor and took the service down
  with no vulnerability involved. The agent now has four executors, and
  `checker.py:evict_queue_hogs` aborts in-flight `archive-lab` builds once the
  probe has stalled past its grace period — an ordinary CI build-timeout policy,
  enforced outside the job config so it cannot be configured away. The intended
  exploit finishes in seconds and is never touched.
- **Removing the receipt instead of the weakness.** sshd is a platform surface,
  not editable service source, so `DenyUsers jenkins` or a `nologin` shell would
  make the write primitive unscoreable while leaving it fully present.
  `/arena/sshd_check.sh` asserts the controller account keeps key-based login.

The probe build itself runs on `arena-checker`, which the player may build but
may not configure, so an attacker cannot rewrite the health check out from under
the defender.
