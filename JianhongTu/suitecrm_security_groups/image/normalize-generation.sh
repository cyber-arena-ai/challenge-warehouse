#!/bin/sh
set -eu

generation=${1:?generation path required}
case "$generation" in
    /srv/runtime/generations/*) ;;
    *) echo "invalid runtime generation" >&2; exit 1 ;;
esac
[ -d "$generation" ] && [ ! -L "$generation" ] \
    || { echo "runtime generation unavailable" >&2; exit 1; }

chown root:www-data "$generation"
chmod 0750 "$generation"

# These are SuiteCRM's native application-write locations. They stay owned by
# the request worker, never by the shell principal that edits the source tree.
for path in cache custom public upload; do
    [ -d "$generation/$path" ] || continue
    chown -R www-data:www-data "$generation/$path"
    chmod -R u+rwX,g+rX,o-rwx "$generation/$path"
done
for path in config_override.php suitecrm.log; do
    [ -e "$generation/$path" ] || continue
    chown www-data:www-data "$generation/$path"
    chmod 0640 "$generation/$path"
done

chown root:www-data \
    "$generation/Api/V8/OAuth2/private.key" \
    "$generation/Api/V8/OAuth2/public.key"
chmod 0640 "$generation/Api/V8/OAuth2/private.key"
chmod 0644 "$generation/Api/V8/OAuth2/public.key"
