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

Four cheap moves would otherwise neutralise the round without repairing the
extraction path, so each is now either normalised away or a health failure:

- **Amputating the attack surface.** `archive-lab` is the job a scoped
  maintainer configures and builds. Disabling it, turning its Groovy sandbox off
  (which parks every future build behind admin script approval the player can
  never obtain), or dropping a `player` grant from its authorization matrix all
  leave Jenkins answering normally.

  Rather than enumerate those, `checker.py:normalize_attack_surface` resets the
  whole configuration to the baseline `init.groovy` captured before anyone could
  touch it, splicing the current Pipeline script back in. The attack needs
  exactly one thing from Configure — rewriting that script — so the attacker
  keeps everything they need and nobody keeps anything else. That also covers
  what a targeted repair missed: added parameters, a dropped concurrent-build
  limit, and an installed timer trigger, each of which is only useful for
  denying service.

  It repairs rather than fails on purpose: the `player` credential is shared, so
  `archive-lab`'s config is writable by the *attacker* too, and failing the round
  would hand them a free SLA kill — disable the victim's job and their health
  check never recovers. Only a job that is gone, or a missing baseline, is a hard
  failure. A narrow fix to the controller-side extraction trips none of this.
- **Killing the agent.** Build steps execute as `jenkins_worker`, the same OS
  user that owns the agent process, so one `sh 'pkill -f agent.jar'` once took
  the service down outright. `/arena/agent_supervisor.sh` runs as root, reaps
  that user and respawns the agent. The reap is the load-bearing half:
  durable-task keeps a build's shell alive across an agent disconnect, so a
  backgrounded killer loop would otherwise outlive the agent it killed. It does
  not respawn while the controller is down, so a genuinely dead controller stays
  visibly dead for the health probe.

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
  `/arena/sshd_check.sh` asserts the controller account keeps key-based login:
  a real login shell, pubkey auth on under the effective per-user config, no
  Deny/AllowUsers or Deny/AllowGroups excluding it, and key lookup still bound
  to the on-disk `~/.ssh/authorized_keys` rather than redirected to `/dev/null`
  or delegated to an `AuthorizedKeysCommand`. Network-level blocking of port 22
  is out of this probe's reach — it runs inside the container.

The probe build itself runs on `arena-checker`, which the player may build but
may not configure, so an attacker cannot rewrite the health check out from under
the defender.
