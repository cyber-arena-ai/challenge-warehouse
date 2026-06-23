#!/usr/bin/env bash
# First-boot setup for the reversaar vulbox, then hand off to sshd.
#
#   - generate ssh host keys (offline)
#   - lay down the writable, agent-editable source tree
#       /srv/challenge/reversaar/app   (owned by arena_agent; the agent edits C here)
#   - prepare the runtime dir /home/reversaar (owned by reversaar; the CGI must
#     run here, cwd-checked by its anti-debug constructor) with data/ subdirs
#   - run /arena/restart.sh to build + launch nginx + fcgiwrap (the service)
#   - exec sshd so the defender can log in during DEFENSE
set -e

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# Writable source copy the agent edits and restart.sh rebuilds from.
mkdir -p /srv/challenge/reversaar
cp -a /opt/challenge_src/reversaar/app /srv/challenge/reversaar/app
chown -R arena_agent:arena_agent /srv/challenge/reversaar
chmod -R u+w /srv/challenge/reversaar

# Runtime dir the CGI binary insists on (user reversaar, cwd /home/reversaar).
mkdir -p /home/reversaar/data/users /home/reversaar/data/files
# Static web assets served by nginx.
cp -a /opt/challenge_src/reversaar/app/web /home/reversaar/web
chown -R reversaar:reversaar /home/reversaar
chmod 755 /home/reversaar

mkdir -p /run/reversaar
chown reversaar:reversaar /run/reversaar

/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/reversaar.log)" >&2

exec /usr/sbin/sshd -D -e
