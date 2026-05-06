#!/bin/sh
set -e

# When running as root (worker container), fix ownership of shared volumes
# so the non-root api/beat containers (uid 1000) can write to them.
if [ "$(id -u)" = "0" ]; then
    chown -R 1000:1000 /data/output /data/assets /app/logs 2>/dev/null || true
fi

# Extract any .tar.gz nuclei template archives before starting the service.
TEMPLATE_DIR="/opt/nuclei-external-templates"
ARCHIVE_DIR="/opt/nuclei-template-archives"

mkdir -p "$TEMPLATE_DIR" 2>/dev/null || true

if [ -d "$ARCHIVE_DIR" ]; then
    for f in "$ARCHIVE_DIR"/*.tar.gz; do
        [ -f "$f" ] || continue
        echo "[entrypoint] Extracting nuclei templates: $(basename "$f")"
        tar xzf "$f" --no-same-owner --no-same-permissions -C "$TEMPLATE_DIR" 2>/dev/null || true
    done
    count=$(find "$TEMPLATE_DIR" -name '*.yaml' -o -name '*.yml' | wc -l)
    echo "[entrypoint] Nuclei external templates: $count template(s) in $TEMPLATE_DIR"
fi

exec "$@"
