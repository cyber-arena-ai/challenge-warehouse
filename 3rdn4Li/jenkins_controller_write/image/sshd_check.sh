#!/usr/bin/env bash
# The controller OS account's key-based login is the scoreable receipt for this
# challenge, and sshd is a platform surface rather than editable service source
# (/srv/challenge/jenkins). Blocking that one account leaves the controller-side
# file-write weakness completely unrepaired while making it unscoreable, so it is
# a health failure rather than a defense. Narrowly repairing the extraction path
# — the intended fix — keeps every assertion below green.
set -euo pipefail

user=jenkins

sshd -t

shell="$(getent passwd "${user}" | cut -d: -f7)"
case "${shell}" in
    */nologin | */false | "")
        echo "controller account login shell disabled: ${shell:-<none>}" >&2
        exit 1
        ;;
esac

effective="$(sshd -T -C "user=${user},host=localhost,addr=127.0.0.1")"

value_of() {
    grep -i "^$1 " <<<"${effective}" | head -n 1 | cut -d' ' -f2- || true
}

if [ "$(value_of pubkeyauthentication)" != "yes" ]; then
    echo "public-key authentication is disabled for ${user}" >&2
    exit 1
fi

# Disabling the account is not the only way to sever the receipt: pointing
# AuthorizedKeysFile at /dev/null, or delegating key lookup to a command that
# returns nothing, makes the written key unreadable while every check above
# still passes. Require the stock on-disk key path.
keyfile="$(value_of authorizedkeysfile)"
if ! grep -qw -- ".ssh/authorized_keys" <<<"${keyfile}"; then
    echo "sshd AuthorizedKeysFile no longer reads ~/.ssh/authorized_keys: ${keyfile}" >&2
    exit 1
fi

for directive in authorizedkeyscommand authorizedprincipalsfile; do
    value="$(value_of "${directive}")"
    if [ -n "${value}" ] && [ "${value}" != "none" ]; then
        echo "sshd ${directive} overrides on-disk key lookup: ${value}" >&2
        exit 1
    fi
done

groups="$(id -nG "${user}" 2>/dev/null || true)"

deny_users="$(value_of denyusers)"
if [ -n "${deny_users}" ] && grep -qw -- "${user}" <<<"${deny_users}"; then
    echo "sshd DenyUsers excludes ${user}: ${deny_users}" >&2
    exit 1
fi

allow_users="$(value_of allowusers)"
if [ -n "${allow_users}" ] && ! grep -qw -- "${user}" <<<"${allow_users}"; then
    echo "sshd AllowUsers excludes ${user}: ${allow_users}" >&2
    exit 1
fi

deny_groups="$(value_of denygroups)"
if [ -n "${deny_groups}" ]; then
    for group in ${groups}; do
        if grep -qw -- "${group}" <<<"${deny_groups}"; then
            echo "sshd DenyGroups excludes ${user} via ${group}" >&2
            exit 1
        fi
    done
fi

allow_groups="$(value_of allowgroups)"
if [ -n "${allow_groups}" ]; then
    matched=""
    for group in ${groups}; do
        if grep -qw -- "${group}" <<<"${allow_groups}"; then
            matched="${group}"
            break
        fi
    done
    if [ -z "${matched}" ]; then
        echo "sshd AllowGroups excludes ${user}: ${allow_groups}" >&2
        exit 1
    fi
fi

echo "sshd ok: ${user} retains key-based login"
