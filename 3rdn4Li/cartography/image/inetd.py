#!/usr/bin/env python3
"""Generic inetd-style socket-activation wrapper (reusable template).

Replaces systemd `Accept=true` socket units: bind a port, and per connection
fork a child with the socket on stdin/stdout/stderr, chdir into the service
dir, and exec the handler. Config via env:
    INETD_APP      cwd for the handler          (default /srv/app)
    INETD_PORT     TCP port to listen on        (default 6666)
    INETD_HANDLER  handler argv (shlex-split)   (default: a python runner)
"""
import os
import shlex
import signal
import socket
import sys

APP = os.environ.get("INETD_APP", "/srv/app")
PORT = int(os.environ.get("INETD_PORT", "6666"))
HANDLER = shlex.split(os.environ.get("INETD_HANDLER", "/usr/local/bin/python3 -u runner.py"))

# Force the C locale so toolchain/coreutils emit ASCII (some checkers decode
# ascii). Harmless for binary services.
os.environ.setdefault("LC_ALL", "C")
os.environ.setdefault("LANG", "C")


def _reap(_s, _f):
    # Reap with a real handler — NOT SIGCHLD=SIG_IGN, which is inherited across
    # execv and makes waitpid() fail with ECHILD, breaking a handler's own
    # subprocess exit-code detection.
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break


signal.signal(signal.SIGCHLD, _reap)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT))
srv.listen(64)
print(f"inetd: listening on 0.0.0.0:{PORT}, handler {HANDLER} cwd {APP}", flush=True)

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        continue
    pid = os.fork()
    if pid == 0:
        srv.close()
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        for fd in (0, 1, 2):
            os.dup2(conn.fileno(), fd)
        try:
            os.chdir(APP)
            os.execv(HANDLER[0], HANDLER)
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"exec failed: {e}\n")
            os._exit(1)
    conn.close()
