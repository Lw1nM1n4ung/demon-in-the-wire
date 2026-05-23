# ── Stage 1: pull ProjectDiscovery Go binaries (nuclei / httpx / naabu) ──
FROM debian:bookworm-slim AS pd-tools
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /tools
RUN NUCLEI_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip nuclei -d /tools/ && chmod +x /tools/nuclei
RUN HTTPX_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$HTTPX_URL" -o /tmp/httpx.zip && unzip -o /tmp/httpx.zip httpx -d /tools/ && chmod +x /tools/httpx
RUN NAABU_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/naabu/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$NAABU_URL" -o /tmp/naabu.zip && unzip -o /tmp/naabu.zip naabu -d /tools/ && chmod +x /tools/naabu
# gowitness (v3+ ships as a standalone binary)
RUN GOWITNESS_URL=$(curl -sL https://api.github.com/repos/sensepost/gowitness/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux-amd64[^"]*"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$GOWITNESS_URL" -o /tools/gowitness && chmod +x /tools/gowitness
# katana — ProjectDiscovery web crawler (Go binary)
RUN KATANA_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$KATANA_URL" -o /tmp/katana.zip && unzip -o /tmp/katana.zip katana -d /tools/ && chmod +x /tools/katana

# ── Stage 1.5: build fingerprintx from source (Go toolchain required) ──
# Repo is archived (read-only) and publishes no pre-built binaries.
FROM golang:1.23-bookworm AS fpx-builder
RUN go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

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
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# nikto — official portable install from the upstream git repo
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && rm -rf /opt/nikto/.git

# wpscan — WordPress vulnerability scanner (Ruby gem)
RUN gem install wpscan --no-document \
    && ln -sf /usr/local/bin/wpscan /usr/bin/wpscan

# Python deps (before Go binaries — pip httpx overwrites /usr/local/bin/httpx)
COPY web_portal/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec@v1.5.1
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
RUN KERBRUTE_URL=$(curl -sL https://api.github.com/repos/ropnop/kerbrute/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64"' | head -1 | cut -d'"' -f4) \
    && curl -sL "$KERBRUTE_URL" -o /usr/local/bin/kerbrute \
    && chmod +x /usr/local/bin/kerbrute

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
