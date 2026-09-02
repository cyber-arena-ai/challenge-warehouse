#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/projectsend
LIVE=/var/www/html

mkdir -p "$LIVE/upload/files"
rsync -a --delete --exclude 'upload/files/' "$SOURCE/" "$LIVE/"
rsync -a "$SOURCE/upload/files/" "$LIVE/upload/files/"
chown -R www-data:www-data "$LIVE/cache" "$LIVE/upload"
