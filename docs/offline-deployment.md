# Offline / Air-Gapped Deployment

Detailed reference for Wire_Ghost offline deployment — how the export bundle is built, how the installer works on an air-gapped machine, and how the pieces fit together.

---

## Table of Contents

- [Design Goals](#design-goals)
- [Bundle Architecture](#bundle-architecture)
- [Export Process (`offline-export.sh`)](#export-process-offline-exportsh)
- [Bundle Structure](#bundle-structure)
- [Install Process (`offline-install.sh`)](#install-process-offline-installsh)
- [Configuration Flow](#configuration-flow)
- [Image Loading Strategy](#image-loading-strategy)
- [Compose File Processing](#compose-file-processing)
- [Error Handling](#error-handling)
- [Troubleshooting](#troubleshooting)

---

## Design Goals

The offline deployment system is built around three constraints:

1. **Zero network dependency on the target machine** — no `docker pull`, no `apt install`, no `pip install`. Everything the target needs is in the bundle.
2. **Single-file image transfer** — all Docker images are saved into one `wireghost-images.tar` via `docker save`, loaded via `docker load`. One file to copy, one command to restore.
3. **Same configuration experience as online** — the offline installer asks the same interactive prompts (hostname, port, secrets, logging) as `scripts/install.sh`. The only difference is how the images arrive.

---

## Bundle Architecture

```
┌─ Internet-connected machine ─────────────────────────────────────┐
│                                                                    │
│  offline-export.sh                                                 │
│       │                                                            │
│       ├── docker compose build web / worker (or --pull-only)       │
│       ├── docker pull mysql:8.0 redis:7-alpine nginx:alpine ...    │
│       ├── docker save -o wireghost-images.tar <all images>         │
│       ├── rsync project files → bundle/project/                    │
│       ├── strip build: blocks from docker-compose.yml (Python)     │
│       ├── embed install.sh (heredoc)                               │
│       └── tar czf wireghost-offline-<ts>.tar.gz bundle/            │
│                                                                    │
└─────────────────────┬──────────────────────────────────────────────┘
                      │  USB / SCP / air-gap transfer
                      ▼
┌─ Air-gapped machine ──────────────────────────────────────────────┐
│                                                                    │
│  tar xzf wireghost-offline-<ts>.tar.gz                             │
│  cd wireghost-offline-<ts>/                                        │
│  sudo bash install.sh                                              │
│       │                                                            │
│       ├── docker load < wireghost-images.tar                       │
│       ├── Interactive config (5 sections)                          │
│       ├── Generate TLS cert                                        │
│       ├── Render nginx.conf                                        │
│       ├── Write .env                                               │
│       ├── docker compose up -d (no network needed)                 │
│       └── Health checks → https://<host>:<port>/setup              │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## Export Process (`offline-export.sh`)

### Prerequisites

On the internet-connected build machine:

| Requirement | Check |
|-------------|-------|
| Docker Engine 24+ | `docker --version` |
| Docker Compose v2 | `docker compose version` |
| `rsync` | `apt install rsync` |
| `python3` | Compose file processing |
| Sufficient disk (~10 GB) | For image builds + tar |

### Image Build Strategy

By default (`--pull-only` not set), the script builds two custom images from source:

```
docker compose build web    → callmedemon/wireghost:web    (~180 MB)
docker compose build worker → callmedemon/wireghost:worker (~700 MB)
```

These are tagged to match the `image:` directives in `docker-compose.yml`, so the target machine's Docker Compose uses them directly without needing to build.

With `--pull-only`, the script pulls pre-built images from Docker Hub instead:
```
docker pull callmedemon/wireghost:web
docker pull callmedemon/wireghost:worker
```

With `--with-msf`, the standalone CLI image is also included:
```
docker compose build cli → callmedemon/wireghost:latest (~2 GB)
```
This adds Metasploit Framework (~1.5 GB) on top of the worker image.

Upstream images (`mysql:8.0`, `redis:7-alpine`, `nginx:alpine`, `tecnativa/docker-socket-proxy:latest`) are always pulled — they're never built locally.

### Output

| Output | Size (approx) | Description |
|--------|---------------|-------------|
| `wireghost-offline-<ts>/` | ~2 GB | Uncompressed bundle directory |
| `wireghost-offline-<ts>.tar.gz` | ~1.5 GB | Compressed archive (`--skip-compress` omits this) |
| + with `--with-msf` | +2 GB | Additional Metasploit image |

---

## Bundle Structure

```
wireghost-offline-YYYYMMDD-HHMMSS/
│
├── install.sh                       # Self-contained offline installer
├── wireghost-images.tar             # All Docker images (docker save output)
├── MANIFEST.txt                     # Human-readable contents list
│
└── project/                         # Source tree subset
    ├── docker-compose.yml           # Stripped: only image: directives, no build:
    ├── docker-compose.dev.yml       # Dev overlay (retained as-is)
    ├── Dockerfile                   # Standalone CLI Dockerfile
    │
    ├── config/
    │   ├── .env.example             # Environment template
    │   ├── nginx.conf.tpl           # nginx template (rendered by installer)
    │   └── wireghost.example.yml    # Scan defaults template
    │
    ├── web/                         # SPA frontend (static files served by nginx)
    ├── web_portal/                  # Django API, worker, bot, migrations
    │   ├── Dockerfile               # Worker image Dockerfile
    │   ├── Dockerfile.web           # Web image Dockerfile
    │   ├── requirements.txt
    │   ├── manage.py
    │   ├── scanner/                 # Django app (models, views, tasks, bot, migrations)
    │   └── wireghost_web/           # Django project (settings, celery, urls)
    │
    ├── src/                         # Pipeline library
    │   └── wireghost/
    │       ├── cli.py
    │       ├── config.py
    │       ├── models/
    │       ├── parsers/
    │       ├── pipeline/
    │       └── reports/
    │
    ├── scripts/
    │   ├── wg-ctl                   # Management CLI
    │   ├── remove-wireghost.sh      # Uninstall script
    │   └── offline-install.sh       # Standalone installer (for dev mode)
    │
    └── templates/                   # External nuclei template archives
```

Files intentionally **excluded** from the bundle: `.git/`, `tests/`, `docs/`, `*.pyc`, `__pycache__/`, `.env` (secrets), `logs/`, `output/`, `backups/`, `node_modules/`.

---

## Install Process (`offline-install.sh`)

### Mode Detection

The installer auto-detects its environment using a three-tier check:

```
Is wireghost-images.tar next to the script?
    ├── YES → BUNDLE MODE
    │         PROJECT_DIR = ./project/
    │         IMAGES_TAR  = ./wireghost-images.tar
    │         Images loaded via docker load
    │
    └── NO  → Is wireghost-images.tar in the parent directory?
                ├── YES → PROJECT MODE (running from project/scripts/)
                │         PROJECT_DIR = ../
                │         IMAGES_TAR  = ../wireghost-images.tar
                │         Images loaded via docker load
                │
                └── NO  → STANDALONE / DEV MODE
                          PROJECT_DIR = ../
                          IMAGES_TAR  = (none)
                          Images built via docker compose build
```

This means `scripts/offline-install.sh` can be run:
- Inside a bundle as `install.sh`
- From within a cloned repo as `scripts/offline-install.sh`
- On a machine that has or doesn't have internet — it adapts

### Installation Steps

#### 1. Prerequisite Checks

```
docker --version          → Docker Engine 24+
docker compose version    → Compose v2 plugin
python3 --version         → Required for health checks
Disk: ≥ 10 GB free
RAM: ≥ 4 GB
```

All checks are non-fatal warnings except Docker/Compose/python3 which are hard requirements.

#### 2. Image Loading (Bundle/Project modes only)

```bash
docker load < wireghost-images.tar
```

Loads all six (or seven with MSF) images into the local Docker image store. This typically takes 2–5 minutes depending on disk speed. In dev mode, this step is skipped and images are built via `docker compose build` instead.

#### 3. Interactive Configuration

The same five-section config as the online installer:

| Section | Prompts | Defaults |
|---------|---------|----------|
| **Portal Access** | Hostname, HTTPS port, HTTP port, protocol | `localhost`, `443`, `80`, `https` |
| **MySQL** | Root password, database name, user, user password | Auto-generated |
| **Redis** | Redis password | Auto-generated |
| **Django** | Secret key | Auto-generated 50-char |
| **Logging** | Log directory, log level | `./logs`, `INFO` |

All secrets are generated with `openssl rand -hex 32` if the user accepts the default.

#### 4. TLS Certificate

Self-signed RSA 2048 certificate with 10-year validity. Stored in `certs/`. Users can replace with their own certificates after installation.

#### 5. nginx.conf Rendering

The `config/nginx.conf.tpl` template is rendered via `sed` substitutions for `{{HOSTNAME}}`, `{{HTTPS_PORT}}`, `{{HTTP_PORT}}`. The rendered config is written to `nginx.conf` at the project root.

#### 6. .env Writing

All configured values (including secrets) are written to `.env` with `chmod 600`. This file is never included in backups or bundles.

#### 7. Service Startup

```bash
docker compose up -d
```

Because all images exist locally (loaded from the tar), Docker Compose uses them directly — no pull, no build, no network access required. The compose file has already been stripped of `build:` blocks during export (see below), so there's nothing that could trigger a network-dependent operation.

#### 8. Health Checks

```
MySQL:   docker compose exec db mysqladmin ping
Redis:   docker compose exec redis redis-cli ping
Django:  curl -k https://localhost:<port>/api/auth/check/
```

The installer waits up to 60 seconds for all three checks to pass before printing the success summary.

---

## Configuration Flow

```
User input (interactive prompts)
        │
        ▼
Environment variables (in-memory)
        │
        ├──→ nginx.conf.tpl ──(sed)──→ nginx.conf
        │
        └──→ .env file (chmod 600)
                 │
                 ▼
        docker compose up -d
                 │
                 ▼
        docker-compose.yml ${VAR} interpolation
                 │
                 ▼
        Container environment variables
```

The `.env` file is the single source of truth after installation. All Docker Compose `${VAR}` references resolve from it. The Django settings module reads from the container environment (which Docker Compose populates from `.env`).

---

## Image Loading Strategy

### Why `docker save` / `docker load`

`docker save` produces a single tar archive containing all layers for all specified images. `docker load` restores them atomically. This is the only Docker-native mechanism for transferring images without a registry.

### Why not a local registry?

Running `docker run registry:2` on the target machine would require:
- Configuring Docker daemon to trust the insecure registry
- Pushing images to the local registry
- Pulling via `docker compose`

This adds complexity and more failure modes. `docker load` is a single command with no daemon configuration needed.

### Why a single tar?

All six images (seven with MSF) share base layers (Debian, Python). A single `docker save` deduplicates these layers automatically. Separate tars would duplicate shared layers and increase total size.

---

## Compose File Processing

During export, the `docker-compose.yml` is processed by a Python regex to remove `build:` blocks:

```python
re.sub(r'^(\s*)build:.*\n(?:\1\s+.*\n)*', '', text, flags=re.MULTILINE)
```

This strips the multi-line `build:` directive and its indented sub-keys (context, dockerfile, args, etc.) while preserving the `image:` directive. On the air-gapped machine, Docker Compose sees only `image:` — it uses the locally-loaded image without attempting to build or pull.

Example transformation:
```yaml
# Before (in repo)
api:
    build:
        context: ./web_portal
        dockerfile: Dockerfile.web
    image: callmedemon/wireghost:web

# After (in bundle)
api:
    image: callmedemon/wireghost:web
```

---

## Error Handling

### Export phase (`offline-export.sh`)

| Failure | Behavior |
|---------|----------|
| `docker compose build` fails | Script exits. Check Docker daemon and disk space. |
| `docker pull` fails (upstream images) | Script exits. Check internet and Docker Hub availability. |
| `docker save` fails | Script exits. Check disk space (needs ~2 GB free). |
| `rsync` fails | Script exits. Check source files exist. |
| `tar czf` fails | Script exits (if not `--skip-compress`). Check disk space. |
| Prerequisite missing | Script exits with clear message (e.g., "rsync not installed"). |

### Install phase (`offline-install.sh`)

| Failure | Behavior |
|---------|----------|
| `docker load` fails | Script exits. Check tar integrity and disk space. |
| Config prompts cancelled (Ctrl+C) | Script exits. No partial state written. |
| `docker compose up -d` fails | Script exits. Check `.env` values and port conflicts. |
| Health check timeout (60s) | Warning printed. Services may still come up — check `docker compose ps`. |
| TLS cert generation fails | Script exits. Check `openssl` is installed. |

---

## Troubleshooting

### "docker load: no space left on device"

The image tar is ~2 GB uncompressed during load (Docker extracts layers to `/var/lib/docker`). Ensure at least 10 GB free on the Docker data partition.

```bash
df -h /var/lib/docker
```

Clean up old images if needed:
```bash
docker system prune -a
```

### "manifest for image not found" on docker compose up

Docker Compose is trying to pull an image that wasn't in the tar. Check that:
1. All images loaded successfully (`docker images | grep -E 'wireghost|mysql|redis|nginx|tecnativa'`)
2. The compose file has `image:` directives matching the loaded image tags
3. The compose file was properly stripped of `build:` blocks (if running from a repo clone rather than a bundle)

### "docker compose build" in dev mode with no internet

The installer falls back to `docker compose build` only in dev mode (no tar found). This requires internet for `apt-get` and `pip` inside the Dockerfiles. If you need fully offline dev mode, run the export script first to create a bundle, then use `sudo bash install.sh` from inside the bundle directory.

### Tar file corruption

If the transfer medium (USB, network) corrupted the tar:

```bash
# Verify tar integrity before installing
tar tzf wireghost-offline-*.tar.gz > /dev/null && echo "OK" || echo "CORRUPT"

# Verify images tar integrity
tar tf wireghost-images.tar > /dev/null && echo "OK" || echo "CORRUPT"
```

### Port already in use

If ports 443/80 are already bound:
```bash
# Check what's using the port
sudo ss -tlnp | grep -E ':443|:80'

# Re-run installer and choose different ports
sudo bash install.sh
```

### Services start but portal shows 502

Usually indicates the Django API container hasn't finished starting. Check:
```bash
docker compose logs api | tail -20
```

Common causes: database migrations pending (`docker compose exec api python manage.py migrate`), Redis unreachable, or `.env` values incorrect.
