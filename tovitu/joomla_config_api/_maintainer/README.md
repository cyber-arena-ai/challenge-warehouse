# Joomla configuration API maintainer notes

The package pins `joomla/joomla-cms` at
`e6ffd2c171f8bae3a03d182682ae9a462226c775`, the sole parent of repair
`5897df8ee39056fbd37624eeeeff1b81e24d84ef`. The source archive is overlaid on
the digest-pinned official Joomla 4.2.7 image, which supplies generated assets
and locked PHP dependencies absent from the Git checkout. The Docker build
verifies SHA-256 `3477fb519a5e8ee54a15f79037bb6fc1bcd37e8a08146b8af54e8713cb2cfe69`
for the vulnerable `libraries/src/Router/ApiRouter.php`.

The retained public path reaches the non-public application-configuration API
because caller query data can replace a route's protected publicness default.
Pagination exposes the current SMTP password. Direct-child repair
`5897df8ee39056fbd37624eeeeff1b81e24d84ef` removes the caller-controlled key
before the merge while retaining authenticated configuration GET and PATCH.
The selected evidence is CVE-2023-23752 and the accepted Stage 3 study at
`artifacts/projects/JOOMLA__JOOMLA_CMS/stage3/cve-2023-23752-config-api/`.

The single READ objective uses scope `secret.credential.read`: every round the
facility administrator replaces the SMTP credential through Joomla's guarded
API and verifies it through the same authenticated route. MariaDB listens only
on loopback, so database reachability is not the witness; disclosure of the
protected application credential is the complete scored outcome. The public
path and pagination are non-secret locators, so no flag ID is needed.

The deep external checker preserves the public homepage, a normal Registered
login, and a randomized administrator configuration PATCH followed by GET. It
uses target-specific Registered and Super User identities derived from facility
state and provisioned through Joomla's supported CLI before round 0. Their
plaintext credentials are not baked or written to challenge-owned credential
files, and they never enter attacker-visible principal records. The checker
reaches Joomla only through the framework-provided host and public port, uses
`fromname` as checker-owned noise, and never reads or changes the scoring
credential. Removing the configuration route, returning a canned response, or
blocking normal sign-in fails health; applying the exact router repair preserves
all declared workflows.
