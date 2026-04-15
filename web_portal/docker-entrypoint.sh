#!/bin/sh
# Extract any .tar.gz nuclei template archives before starting the service.
TEMPLATE_DIR="/opt/nuclei-external-templates"
ARCHIVE_DIR="/opt/nuclei-template-archives"

mkdir -p "$TEMPLATE_DIR"

if [ -d "$ARCHIVE_DIR" ]; then
    for f in "$ARCHIVE_DIR"/*.tar.gz; do
        [ -f "$f" ] || continue
        echo "[entrypoint] Extracting nuclei templates: $(basename "$f")"
        tar xzf "$f" -C "$TEMPLATE_DIR"
    done
    count=$(find "$TEMPLATE_DIR" -name '*.yaml' -o -name '*.yml' | wc -l)
    echo "[entrypoint] Nuclei external templates: $count template(s) in $TEMPLATE_DIR"
fi

exec "$@"
