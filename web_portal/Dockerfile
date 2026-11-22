# ── Stage 1: pull ProjectDiscovery Go binaries (nuclei / httpx / naabu) ──
FROM debian:bookworm-slim AS pd-tools
# NOTE: apt-get update exits 0 even when every repo fetch fails, so this
# layer cannot be retried in place. Keep the command text stable so the
# builder cache can be reused when a mirror is briefly unreachable.
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
# GitHub release downloads are unreliable from container networks: the TLS
# connection is frequently reset (curl exit 35) and DNS may resolve only an
# unreachable edge IP. fetch_release.sh handles both.
WORKDIR /tools
COPY web_portal/fetch_release.sh /usr/local/bin/fetch_release.sh
RUN chmod +x /usr/local/bin/fetch_release.sh
RUN fetch_release.sh projectdiscovery/nuclei linux_amd64.zip /tmp/nuclei.zip nuclei \
    && chmod 0755 /tools/nuclei
RUN fetch_release.sh projectdiscovery/httpx linux_amd64.zip /tmp/httpx.zip httpx \
    && chmod 0755 /tools/httpx
RUN fetch_release.sh projectdiscovery/naabu linux_amd64.zip /tmp/naabu.zip naabu \
    && chmod 0755 /tools/naabu
# gowitness (v3+ ships as a standalone binary)
RUN fetch_release.sh sensepost/gowitness linux-amd64 /tmp/gowitness.bin \
    && install -m 0755 /tmp/gowitness.bin /tools/gowitness
# katana — ProjectDiscovery web crawler (Go binary)
RUN fetch_release.sh projectdiscovery/katana linux_amd64.zip /tmp/katana.zip katana \
    && chmod 0755 /tools/katana

# ── Stage 1.5: build fingerprintx from source (Go toolchain required) ──
# Repo is archived (read-only) and publishes no pre-built binaries.
FROM golang:1.23-bookworm AS fpx-builder
# Module downloads are reset intermittently; retry the whole install.
RUN for i in 1 2 3 4 5; do \
        go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest && break || \
        { echo "go install attempt $i failed, retrying"; sleep 10; }; \
    done \
    && test -x /go/bin/fingerprintx

# ── Stage 2: final image ──
FROM python:3.12-slim-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

# System deps: MySQL client + scan tools. Nikto is installed from the
# upstream repo because Debian doesn't ship a native `nikto` package here.
# Nuclei / httpx / naabu are copied from the builder stage above.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc default-libmysqlclient-dev pkg-config \
    nmap fping masscan git libpcap0.8 \
    chromium perl libnet-ssleay-perl libio-socket-ssl-perl \
    libjson-perl libxml-writer-perl libxml-libxml-perl \
    sslscan snmp nfs-common ldap-utils curl unzip \
    ruby ruby-dev build-essential libcurl4 \
    && rm -rf /var/lib/apt/lists/*

# searchsploit (exploitdb) — shallow clone to keep image size reasonable.
RUN for i in 1 2 3 4 5; do \
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && break || \
        { echo "exploitdb clone attempt $i failed, retrying"; rm -rf /opt/exploitdb; sleep 10; }; \
    done \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# nikto — official portable install from the upstream git repo
RUN for i in 1 2 3 4 5; do \
        git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && break || \
        { echo "nikto clone attempt $i failed, retrying"; rm -rf /opt/nikto; sleep 10; }; \
    done \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && rm -rf /opt/nikto/.git

# wpscan — WordPress vulnerability scanner (Ruby gem)
RUN gem install wpscan --no-document \
    && ln -sf /usr/local/bin/wpscan /usr/bin/wpscan

# Python deps (before Go binaries — pip httpx overwrites /usr/local/bin/httpx)
COPY web_portal/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN for i in 1 2 3 4 5; do \
        pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git && break || \
        { echo "NetExec install attempt $i failed, retrying"; sleep 10; }; \
    done || echo "NetExec install skipped (optional — pipeline will skip nxc if unavailable)"
RUN pip install --no-cache-dir getsploit

# ProjectDiscovery Go binaries + gowitness (AFTER pip to avoid overwrite)
COPY --from=pd-tools /tools/nuclei    /usr/local/bin/nuclei
COPY --from=pd-tools /tools/httpx     /usr/local/bin/httpx
COPY --from=pd-tools /tools/naabu     /usr/local/bin/naabu
COPY --from=pd-tools /tools/gowitness /usr/local/bin/gowitness
COPY --from=pd-tools /tools/katana    /usr/local/bin/katana

# fingerprintx — service fingerprinting for web detection refinement
COPY --from=fpx-builder /go/bin/fingerprintx /usr/local/bin/fingerprintx

# kerbrute — Kerberos brute-force (pre-built binary from GitHub)
COPY web_portal/fetch_release.sh /usr/local/bin/fetch_release.sh
RUN chmod +x /usr/local/bin/fetch_release.sh
RUN fetch_release.sh ropnop/kerbrute linux_amd64 /tmp/kerbrute.bin \
    && install -m 0755 /tmp/kerbrute.bin /usr/local/bin/kerbrute

# App code
COPY web_portal/ .
COPY src/ /app/src/

# Nuclei external templates — extract any .tar.gz archives at build time
COPY templates/ /opt/nuclei-template-archives/
RUN mkdir -p /opt/nuclei-external-templates \
    && for f in /opt/nuclei-template-archives/*.tar.gz; do \
         [ -f "$f" ] && tar xzf "$f" -C /opt/nuclei-external-templates/ || true; \
       done \
    && echo "Nuclei external templates: $(find /opt/nuclei-external-templates -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l) template(s)"

# Entrypoint extracts any new .tar.gz added via volume mount at runtime
COPY web_portal/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

RUN groupadd -g 1000 appuser && useradd -u 1000 -g 1000 -m -s /bin/sh appuser \
    && mkdir -p /data/output /data/assets /app/logs \
    && chown -R appuser:appuser /data /app/logs

RUN find / -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null; \
    find / -perm -2000 -type f -exec chmod g-s {} + 2>/dev/null; \
    true

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src

EXPOSE 8000
USER appuser
ENTRYPOINT ["/docker-entrypoint.sh"]
