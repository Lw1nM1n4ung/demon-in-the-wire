# === Stage 1: Download pre-built Go tool binaries ===
FROM debian:bookworm-slim AS tools
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# nuclei
RUN NUCLEI_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$NUCLEI_URL" -o nuclei.zip \
    && unzip -o nuclei.zip nuclei -d /tools/ \
    && chmod +x /tools/nuclei && rm nuclei.zip

# httpx
RUN HTTPX_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$HTTPX_URL" -o httpx.zip \
    && unzip -o httpx.zip httpx -d /tools/ \
    && chmod +x /tools/httpx && rm httpx.zip

# naabu
RUN NAABU_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/naabu/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$NAABU_URL" -o naabu.zip \
    && unzip -o naabu.zip naabu -d /tools/ \
    && chmod +x /tools/naabu && rm naabu.zip

# gowitness (v3+ ships as a standalone binary, not a tarball)
RUN GOWITNESS_URL=$(curl -sL https://api.github.com/repos/sensepost/gowitness/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux-amd64[^"]*"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$GOWITNESS_URL" -o /tools/gowitness \
    && chmod +x /tools/gowitness

# === Stage 2: Final image ===
FROM python:3.12-slim-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping masscan libpcap0.8 libsnmp40 git rsync libxml2-utils \
    chromium \
    smbclient samba-common-bin ldap-utils perl \
    libnet-ssleay-perl libio-socket-ssl-perl \
    libjson-perl libxml-writer-perl libxml-libxml-perl \
    && rm -rf /var/lib/apt/lists/*

# Install enum4linux
RUN git clone --depth 1 https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux \
    && ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux \
    && chmod +x /opt/enum4linux/enum4linux.pl

# Install searchsploit (exploitdb)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp /opt/exploitdb/.searchsploit_rc /root/ 2>/dev/null || true

# Install nikto from the official upstream repo (portable git-based install)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && rm -rf /opt/nikto/.git

# Download Metasploit module metadata (exploit matching, ~50MB)
RUN mkdir -p /opt/msf \
    && curl -sL https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json \
       -o /opt/msf/modules_metadata_base.json \
    && echo "MSF metadata: $(python3 -c "import json; print(len(json.load(open('/opt/msf/modules_metadata_base.json'))))" 2>/dev/null || echo 'download failed') modules"

# Copy pre-built tool binaries
COPY --from=tools /tools/nuclei /usr/local/bin/nuclei
COPY --from=tools /tools/httpx /usr/local/bin/httpx
COPY --from=tools /tools/naabu /usr/local/bin/naabu
COPY --from=tools /tools/gowitness /usr/local/bin/gowitness

# Install wireghost
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir . netexec

# Download nuclei templates
RUN nuclei -update-templates

# Verify all tools
RUN echo "=== Tool verification ===" \
    && nmap --version | head -1 \
    && fping -v 2>&1 | head -1 \
    && nuclei -version 2>&1 | head -1 \
    && naabu -version 2>&1 | head -1 \
    && masscan --version 2>&1 | head -1 \
    && gowitness version 2>&1 | head -1 \
    && wireghost --version

RUN find / -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null; \
    find / -perm -2000 -type f -exec chmod g-s {} + 2>/dev/null; \
    true

ENV WIREGHOST_OUTPUT_DIR=/data/output
ENTRYPOINT ["wireghost"]
