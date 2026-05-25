#!/bin/sh
# ══════════════════════════════════════════════════════════════════════
# Portal entrypoint — renders nginx config from template using env vars
# passed via docker-compose (WIREGHOST_HOST, WIREGHOST_PORT).
# This allows the same portal image to be deployed to any host without
# rebuilding — just set WIREGHOST_HOST in .env and restart the container.
# ══════════════════════════════════════════════════════════════════════
set -e

HOST="${WIREGHOST_HOST:-localhost}"
PORT="${WIREGHOST_PORT:-443}"

sed -e "s/{{WIREGHOST_HOST}}/${HOST}/g" \
    -e "s/{{WIREGHOST_PORT}}/${PORT}/g" \
    /etc/nginx/conf.d/default.conf.tpl > /etc/nginx/conf.d/default.conf

exec nginx -g "daemon off;"
