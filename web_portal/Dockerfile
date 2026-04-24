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

# ── Stage 2: final image ──
FROM python:3.12-slim

WORKDIR /app

# System deps: MySQL client + scan tools (nmap, fping, masscan, searchsploit).
# Nuclei / httpx / naabu are copied from the builder stage above.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc default-libmysqlclient-dev pkg-config \
    nmap fping masscan git libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery binaries
COPY --from=pd-tools /tools/nuclei /usr/local/bin/nuclei
COPY --from=pd-tools /tools/httpx  /usr/local/bin/httpx
COPY --from=pd-tools /tools/naabu  /usr/local/bin/naabu

# searchsploit (exploitdb) — shallow clone to keep image size reasonable.
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Python deps
COPY web_portal/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
    && chown -R appuser:appuser /data /app/logs /opt/nuclei-external-templates

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src

EXPOSE 8000
USER appuser
ENTRYPOINT ["/docker-entrypoint.sh"]
