#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-wireghost-test-secret}"

echo "==> pytest"
python3 -m pytest tests -q

echo "==> django"
(
  cd web_portal
  python3 manage.py test scanner --verbosity=1
)

echo "==> frontend-js"
node tests/test_frontend_js.js

echo "==> topology-js"
node tests/test_topology_js.js

echo "==> installers"
bash tests/test_installers.sh
