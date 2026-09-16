#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A
mkdir -p /run/sshd /srv/challenge /var/lib/gradio-arena/{proofs,public}

chown root:appuser /var/lib/gradio-arena /var/lib/gradio-arena/proofs
chmod 0750 /var/lib/gradio-arena /var/lib/gradio-arena/proofs
chown appuser:appuser /var/lib/gradio-arena/public
chmod 0700 /var/lib/gradio-arena/public
mkdir -p /tmp/gradio /tmp/matplotlib
chown -R appuser:appuser /tmp/gradio /tmp/matplotlib

exec /usr/sbin/sshd -D -e
