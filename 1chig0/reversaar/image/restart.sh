#!/usr/bin/env bash
# Rebuild reversaar from the agent-editable source and relaunch the service.
# Runs as root (privileged docker exec). A broken C edit fails the compile and
# fails the restart (compile gate, SOP §7).
#
#   1. compile reversaar.cgi + .tmp.bin from /srv/challenge/reversaar/app  (FAST
#      mode: no obfuscation, deterministic + offline)
#   2. install the fresh binaries into /home/reversaar (the CGI's required cwd)
#   3. (re)start nginx + spawn-fcgi(fcgiwrap) as user reversaar
#   4. health-probe http://127.0.0.1:7331/
set -e

SRC="/srv/challenge/reversaar/app"
RUN="/home/reversaar"
LOG="/var/log/reversaar.log"
PORT=7331
SOCK="/run/reversaar/reversaar.sock"

mkdir -p "$(dirname "$LOG")" /run/reversaar
chown reversaar:reversaar /run/reversaar

# ---- compile gate -------------------------------------------------------------
# Build as the source owner so target artifacts are writable on the next rebuild.
runuser -u arena_agent -- /arena/build_service.sh "$SRC" fast

# ---- install artifacts into the runtime dir ----------------------------------
install -o reversaar -g reversaar -m 0755 "$SRC/reversaar.cgi" "$RUN/reversaar.cgi"
install -o reversaar -g reversaar -m 0644 "$SRC/.tmp.bin"      "$RUN/.tmp.bin"
mkdir -p "$RUN/data/users" "$RUN/data/files"
chown -R reversaar:reversaar "$RUN/data"

# ---- (re)launch fcgiwrap + nginx ---------------------------------------------
pkill -f 'fcgiwrap' || true
pkill -x 'spawn-fcgi' || true
nginx -s stop 2>/dev/null || true
for _ in $(seq 1 20); do pgrep -f 'fcgiwrap' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'fcgiwrap' 2>/dev/null || true
pkill -9 -x 'spawn-fcgi' 2>/dev/null || true
rm -f "$SOCK"

# spawn-fcgi runs fcgiwrap, which exec()s the CGI per request with cwd=/home/reversaar
# (-d) as user reversaar (-u/-g). The socket is world-rw so nginx (www-data) reaches it.
spawn-fcgi -s "$SOCK" -M 0666 -u reversaar -g reversaar -d "$RUN" \
    -- /usr/sbin/fcgiwrap > "$LOG" 2>&1
chown reversaar:reversaar "$SOCK" 2>/dev/null || true

nginx -t >> "$LOG" 2>&1
nginx >> "$LOG" 2>&1 || nginx -s reload >> "$LOG" 2>&1

# ---- health probe -------------------------------------------------------------
for _ in $(seq 1 25); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
    if [ "$code" = "200" ]; then
        echo "reversaar restarted; GET / -> 200"
        exit 0
    fi
    sleep 1
done
echo "reversaar failed to become healthy after restart (last GET / -> ${code:-none})" >&2
exit 1
