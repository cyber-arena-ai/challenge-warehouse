#!/bin/sh
set -eu

runtime=$1
candidate=$2
previous=$3
generations=$runtime/generations

case "$candidate" in
    "$generations"/*) [ -d "$candidate" ] && [ ! -L "$candidate" ] ;;
    *) echo "candidate SuiteCRM generation invalid" >&2; exit 1 ;;
esac
case "$previous" in
    "$generations"/*) [ -d "$previous" ] && [ ! -L "$previous" ] ;;
    *) echo "previous SuiteCRM generation invalid" >&2; exit 1 ;;
esac
[ "$(readlink -f "$runtime/current")" = "$candidate" ] || {
    echo "candidate SuiteCRM generation is not serving" >&2
    exit 1
}

last_good_link="$runtime/.last-good.$$"
ln -s "$candidate" "$last_good_link"
mv -Tf "$last_good_link" "$runtime/last-good"
if [ "$previous" != "$candidate" ]; then
    rm -rf "$previous"
fi

[ "$(readlink -f "$runtime/current")" = "$candidate" ]
[ "$(readlink -f "$runtime/last-good")" = "$candidate" ]
[ -d "$candidate" ]
