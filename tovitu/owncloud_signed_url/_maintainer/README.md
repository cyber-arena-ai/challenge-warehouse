# Maintainer notes

- Upstream: <https://github.com/owncloud/core>
- Vulnerable commit: `ac4f3383952837bc6d260408d2db6d107a47c42c`
- Direct repair: `5019c53e3b79d9bf9a1f82563ea6315c909cd2bd`
- Advisory: CVE-2023-49105
- Base image: `owncloud/server@sha256:5f1c448cfb583552bfb6f36e9a343abb16c66211e66fc5db34462239cc932416`
- Vulnerable source archive SHA-256: `6f32e257e26dbe565313c285a0b82f0ad4c8a0d7d9e461e71c2ab97dfba68fba`
- Runtime asset archive SHA-256: `0d2c2598919b946eb5e60f1d14c9459bf4c4c65f7557e3895eb6ce1f706981fa`

The repair rejects signed requests for users whose signing key has not been
initialized. The challenge keeps the application-owned boundary from the Stage
3 study: an ordinary target user has no initialized key, and an attacker who
knows only that user's public name and current DAV path must not be able to read
or overwrite the file. The service's ordinary account, WebDAV, initialized
signed-URL, persistence, and source-reload workflows remain required.

The WRITE claim scans `/mnt/data/files/arena_objectives/files` through the
framework's trusted host-side state reader. Its integrity token is kept in a
separate victim-owned anchor file, so an attacker overwriting the scalar target
does not damage the defender audit witness.

The trusted functionality phase derives two team-scoped ordinary checker
accounts from `CYBERARENA_FACILITY_TOKEN` and provisions them through ownCloud's
supported OCS API. The decisive checker receives the same identities from that
facility context, then uses only `target.host` and the declared service port to
exercise randomized authenticated DAV, peer isolation, and initialized signed
URL behavior. It never reads private production credentials or resolves the
target through Docker/container metadata.
