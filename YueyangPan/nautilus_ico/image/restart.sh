#!/usr/bin/env bash
# Framework restart script for nautilus-ico.
#
# Invoked by the MCP `restart_service` tool via docker exec (root).
# Mode 555, root-owned — the agent can read + execute but not modify.
# The only path from agent edit to running binary is this script.

set -e

SRC_DIR="/srv/challenge/ico"
BIN="${SRC_DIR}/ico"
LOG="/var/log/ico.stdout"

cd "${SRC_DIR}"

# Same flags as the build-time pre-compile (upstream Makefile release config).
fpc -vh -Sd -Un -Cg -Cr- -Co- -O3 -Px86_64 -oico ico.pas

# Kill any prior instance — fresh container has none, hence `|| true`.
pkill -f "${BIN}" || true
for _ in $(seq 1 10); do pgrep -f "${BIN}" >/dev/null 2>&1 || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f "${BIN}" 2>/dev/null || true

# Logs to a fixed path the SERVICE_LOG artifact hook reads.
mkdir -p "$(dirname "${LOG}")"
nohup "${BIN}" > "${LOG}" 2>&1 &

# Brief settle so a TCP probe right after restart sees the bound port.
sleep 0.5

echo "ico restarted, pid=$(pgrep -f "${BIN}" | head -1)"
