# === Stage 1: Download pre-built Go tool binaries ===
FROM debian:bookworm-slim AS tools

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# nuclei
RUN NUCLEI_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && echo "Downloading nuclei from: $NUCLEI_URL" \
    && curl -sL "$NUCLEI_URL" -o nuclei.zip \
    && unzip -o nuclei.zip nuclei -d /tools/ \
    && chmod +x /tools/nuclei && rm nuclei.zip

# httpx
RUN HTTPX_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && echo "Downloading httpx from: $HTTPX_URL" \
    && curl -sL "$HTTPX_URL" -o httpx.zip \
    && unzip -o httpx.zip httpx -d /tools/ \
    && chmod +x /tools/httpx && rm httpx.zip

# naabu
RUN NAABU_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/naabu/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && echo "Downloading naabu from: $NAABU_URL" \
    && curl -sL "$NAABU_URL" -o naabu.zip \
    && unzip -o naabu.zip naabu -d /tools/ \
    && chmod +x /tools/naabu && rm naabu.zip

# === Stage 2: Final image ===
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping masscan libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built tool binaries
COPY --from=tools /tools/nuclei /usr/local/bin/nuclei
COPY --from=tools /tools/httpx /usr/local/bin/httpx
COPY --from=tools /tools/naabu /usr/local/bin/naabu

# Install wireghost
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir .

# Verify all tools
RUN echo "=== Tool verification ===" \
    && nmap --version | head -1 \
    && fping -v 2>&1 | head -1 \
    && nuclei -version 2>&1 | head -1 \
    && naabu -version 2>&1 | head -1 \
    && masscan --version 2>&1 | head -1 \
    && wireghost --version

ENTRYPOINT ["wireghost"]
