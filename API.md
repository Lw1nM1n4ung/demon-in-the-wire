# Wire_Ghost API Documentation

**Base URL:** `http://localhost:9999/api/` (via Nginx proxy) or `http://localhost:8000/api/` (direct)

**Auth:** None (open API — configure auth in production)  
**Pagination:** `PageNumberPagination`, 50 per page (`?page=2`)  
**Format:** JSON

---

## Dashboard

### `GET /api/dashboard/`

Aggregate statistics across all scans.

**Response:**
```json
{
  "total_scans": 7,
  "running_scans": 1,
  "total_hosts": 99,
  "total_findings": 313,
  "severity": {
    "critical": 19,
    "high": 49,
    "medium": 116,
    "low": 92,
    "info": 37
  },
  "sources": {
    "nuclei": 180,
    "nmap_vuln": 45,
    "service_enum": 30,
    "searchsploit": 28,
    "wpscan": 15,
    "openvas": 15
  },
  "recent_scans": [ ... ]
}
```

---

## Scans

### `GET /api/scans/`

List all scans (lightweight serializer).

**Query params:** none  
**Response:** Paginated list of `ScanListSerializer`

```json
{
  "count": 7,
  "results": [
    {
      "id": 1,
      "name": "Internal Network Sweep",
      "target": "192.168.1.0/24",
      "scan_type": "full",
      "status": "completed",
      "hosts_count": 23,
      "findings_count": 89,
      "critical_count": 6,
      "high_count": 14,
      "medium_count": 31,
      "duration_seconds": 2734,
      "created_at": "2026-04-11T08:30:00Z"
    }
  ]
}
```

### `POST /api/scans/`

Create and launch a new scan. Dispatches a Celery task immediately.

**Request body:**
```json
{
  "target": "192.168.1.0/24",
  "name": "Internal Sweep",
  "scan_type": "full",
  "parallelism": 10,
  "timeout": 3600,
  "report_formats": "dashboard,docx,xlsx",
  "version_detect": true,
  "os_detect": true,
  "service_enum": true,
  "skip_nuclei": false,
  "skip_openvas": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | **required** | IP, CIDR, or hostname |
| `name` | string | `"Scan {target}"` | Display name |
| `scan_type` | enum | `"full"` | `full`, `quick`, `port`, `web`, `service` |
| `parallelism` | int | `10` | Concurrent scan threads (1-100) |
| `timeout` | int | `3600` | Max scan duration in seconds |
| `report_formats` | string | `"dashboard,html,docx,xlsx"` | Comma-separated formats |
| `version_detect` | bool | `true` | Enable nmap `-sV` |
| `os_detect` | bool | `true` | Enable nmap `-O` |
| `service_enum` | bool | `true` | Run service enumeration |
| `skip_nuclei` | bool | `false` | Skip Nuclei scanner |
| `skip_openvas` | bool | `true` | Skip OpenVAS scanner |

**Response:** `201 Created` — Full `ScanSerializer` with `status: "running"`

### `GET /api/scans/{id}/`

Full scan detail including nested reports.

**Response:**
```json
{
  "id": 1,
  "name": "Internal Network Sweep",
  "target": "192.168.1.0/24",
  "scan_type": "full",
  "status": "completed",
  "parallelism": 10,
  "timeout": 3600,
  "report_formats": "dashboard,docx,xlsx",
  "version_detect": true,
  "os_detect": true,
  "service_enum": true,
  "skip_nuclei": false,
  "skip_openvas": true,
  "hosts_count": 23,
  "ports_count": 187,
  "findings_count": 89,
  "critical_count": 6,
  "high_count": 14,
  "medium_count": 31,
  "low_count": 28,
  "info_count": 10,
  "started_at": "2026-04-11T08:30:00Z",
  "completed_at": "2026-04-11T09:15:34Z",
  "duration_seconds": 2734,
  "output_dir": "/data/output/192.168.1.0_24",
  "celery_task_id": "a1b2c3d4-...",
  "error_message": "",
  "created_at": "2026-04-11T08:30:00Z",
  "reports": [
    { "id": 1, "format": "dashboard", "file_path": "...", "file_size": 245760, "created_at": "..." },
    { "id": 2, "format": "docx", "file_path": "...", "file_size": 189440, "created_at": "..." }
  ]
}
```

### `PUT /api/scans/{id}/` · `PATCH /api/scans/{id}/`

Update scan record.

### `DELETE /api/scans/{id}/`

Delete scan and all related hosts, findings, reports.

### `POST /api/scans/{id}/cancel/`

Cancel a running scan. Revokes the Celery task.

**Response:** Updated `ScanSerializer` with `status: "cancelled"`

### `GET /api/scans/{id}/findings/`

Findings for a specific scan with filters.

**Query params:**
| Param | Description |
|-------|-------------|
| `severity` | Filter: `critical`, `high`, `medium`, `low`, `info` |
| `source` | Filter: `nuclei`, `nmap_vuln`, `service_enum`, `searchsploit`, `wpscan`, `openvas` |
| `search` | Search title (case-insensitive contains) |

**Response:** List of `FindingListSerializer`

### `GET /api/scans/{id}/hosts/`

All hosts discovered in a scan.

**Response:** List of `HostListSerializer`

### `POST /api/scans/{id}/regenerate_reports/`

Re-generate reports for a completed scan using current `ReportConfig` branding.

**Request body (optional):**
```json
{
  "formats": ["docx", "xlsx"]
}
```

**Response:**
```json
{
  "task_id": "celery-task-id",
  "status": "queued"
}
```

---

## Hosts

### `GET /api/hosts/`

List all hosts across all scans.

**Response:**
```json
{
  "results": [
    {
      "id": 1,
      "ip": "192.168.1.10",
      "hostname": "web-srv-01.local",
      "os": "Ubuntu 22.04",
      "ports_count": 9,
      "findings_count": 15
    }
  ]
}
```

### `GET /api/hosts/{id}/`

Host detail with nested ports and technologies.

**Response:**
```json
{
  "id": 2,
  "ip": "192.168.1.10",
  "hostname": "web-srv-01.local",
  "os": "Ubuntu 22.04",
  "status": "up",
  "ports_count": 9,
  "findings_count": 15,
  "ports": [
    { "id": 1, "number": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_product": "OpenSSH", "service_version": "8.9p1" },
    { "id": 2, "number": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_product": "nginx", "service_version": "1.24.0" }
  ],
  "technologies": [
    { "id": 1, "name": "nginx", "version": "1.24.0", "url": "https://192.168.1.10" }
  ]
}
```

---

## Findings

### `GET /api/findings/`

List all findings across all scans with filters.

**Query params:**
| Param | Description |
|-------|-------------|
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `source` | `nuclei`, `nmap_vuln`, `service_enum`, `searchsploit`, `wpscan`, `openvas` |
| `search` | Search title |
| `scan` | Filter by scan ID |

**Response:** Paginated list of `FindingListSerializer`
```json
{
  "results": [
    {
      "id": 1,
      "source": "nuclei",
      "severity": "critical",
      "title": "Apache Log4j RCE (CVE-2021-44228)",
      "host_ip": "192.168.1.10",
      "port": "8080",
      "cve": "CVE-2021-44228",
      "full_url": "http://192.168.1.10:8080/api/v1/login"
    }
  ]
}
```

### `GET /api/findings/{id}/`

Full finding detail with evidence.

**Response:**
```json
{
  "id": 1,
  "scan": 1,
  "host": 2,
  "source": "nuclei",
  "severity": "critical",
  "title": "Apache Log4j RCE (CVE-2021-44228)",
  "description": "Apache Log4j2 <=2.14.1 JNDI features...",
  "host_ip": "192.168.1.10",
  "port": "8080",
  "protocol": "tcp",
  "endpoint": "/api/v1/login",
  "full_url": "http://192.168.1.10:8080/api/v1/login",
  "template_id": "CVE-2021-44228",
  "cve": "CVE-2021-44228",
  "cwe": "CWE-502",
  "cvss": "10.0",
  "request": "GET /api/v1/login HTTP/1.1\nHost: 192.168.1.10:8080\n...",
  "response": "HTTP/1.1 200 OK\n...",
  "curl_command": "curl -H 'X-Forwarded-For: ${jndi:ldap://...' ...",
  "raw_output": "",
  "references": "[\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\"]",
  "created_at": "2026-04-11T09:00:00Z"
}
```

---

## Reports

### `GET /api/reports/{id}/download/`

Download a generated report file.

**Response:** File download with appropriate MIME type:
| Format | Content-Type |
|--------|-------------|
| `dashboard` | `text/html` |
| `html` | `text/html` |
| `docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

---

## Report Configuration

### `GET /api/report-config/`

Get current report branding and section configuration (singleton).

**Response:**
```json
{
  "report_title": "Vulnerability Assessment Report",
  "company_name": "Your Company",
  "prepared_by": "Security Team",
  "reviewed_by": "",
  "approved_by": "",
  "logo_path": "/data/assets/logos/logo.png",
  "brand_color": "#006D38",
  "include_cover": true,
  "include_executive_summary": true,
  "include_target_subnets": true,
  "include_live_hosts": true,
  "include_open_ports": true,
  "include_findings": true,
  "include_evidence": true,
  "default_formats": "dashboard,docx,xlsx",
  "disclaimer": "This report is confidential...",
  "updated_at": "2026-04-11T12:00:00Z"
}
```

### `PUT /api/report-config/`

Update report configuration (partial updates supported).

**Request body (any subset):**
```json
{
  "company_name": "New Corp",
  "brand_color": "#1a5276",
  "include_evidence": false
}
```

### `POST /api/report-config/logo/`

Upload a custom logo for report cover pages.

**Request:** `multipart/form-data` with `logo` file field

**Response:**
```json
{
  "logo_path": "/data/assets/logos/logo.png",
  "filename": "logo.png"
}
```

---

## Django Admin

**URL:** `http://localhost:9999/admin/`  
**Credentials:** `admin` / `admin` (created on first `docker compose up`)

---

## Docker Compose Services

```bash
docker compose up -d          # Start all services
docker compose ps             # Check status
docker compose logs api       # API logs
docker compose logs worker    # Celery worker logs
docker compose down           # Stop all
```

| Service | Port | Description |
|---------|------|-------------|
| `db` | 3306 | MySQL 8.0 |
| `redis` | 6379 | Celery broker |
| `api` | 8000 | Django REST API |
| `worker` | — | Celery scan worker |
| `portal` | **9999** | Nginx frontend |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MYSQL_HOST` | `127.0.0.1` | MySQL host |
| `MYSQL_PORT` | `3306` | MySQL port |
| `MYSQL_DATABASE` | `wireghost` | Database name |
| `MYSQL_USER` | `wireghost` | Database user |
| `MYSQL_PASSWORD` | `wireghost_pass` | Database password |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Redis broker URL |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Redis result backend |
| `WIREGHOST_OUTPUT_DIR` | `/data/output` | Scan output directory |

## Database Schema

```
scanner_scan           → Scan jobs (target, status, counts, timing)
  ├── scanner_host     → Discovered hosts (ip, hostname, os)
  │   ├── scanner_port        → Open ports (number, protocol, service)
  │   └── scanner_technology  → Detected technologies (name, version)
  ├── scanner_finding  → Vulnerabilities (severity, CVE, evidence)
  └── scanner_report   → Generated report files (format, path, size)

scanner_reportconfig   → Singleton branding config
```
