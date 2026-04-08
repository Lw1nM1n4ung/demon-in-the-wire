# === Stage 1: Download pre-built Go tool binaries ===
FROM debian:bookworm-slim AS tools

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

# === Stage 2: Final image ===
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping masscan libpcap0.8 git \
    && rm -rf /var/lib/apt/lists/*

# Install searchsploit (exploitdb)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp /opt/exploitdb/.searchsploit_rc /root/ 2>/dev/null || true

# Copy pre-built tool binaries
COPY --from=tools /tools/nuclei /usr/local/bin/nuclei
COPY --from=tools /tools/httpx /usr/local/bin/httpx
COPY --from=tools /tools/naabu /usr/local/bin/naabu

# Install wireghost + gvm-tools
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir . gvm-tools

# Download nuclei templates + update searchsploit db
RUN nuclei -update-templates
RUN searchsploit -u 2>/dev/null || true

# Verify all tools
RUN echo "=== Tool verification ===" \
    && nmap --version | head -1 \
    && fping -v 2>&1 | head -1 \
    && nuclei -version 2>&1 | head -1 \
    && naabu -version 2>&1 | head -1 \
    && masscan --version 2>&1 | head -1 \
    && searchsploit --version 2>&1 | head -1 || true \
    && gvm-cli --version 2>&1 | head -1 \
    && wireghost --version

ENV WIREGHOST_OUTPUT_DIR=/data/output
ENTRYPOINT ["wireghost"]
