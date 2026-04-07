# === Stage 1: Build Go tools ===
FROM golang:1.22-bookworm AS go-builder

ENV GONOSUMCHECK=* GONOSUMDB=* GOFLAGS="-buildvcs=false"

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# === Stage 2: Final image ===
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping masscan libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tool binaries from builder
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-builder /go/bin/naabu /usr/local/bin/naabu

# Install wireghost
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir .

# Verify all tools are available
RUN nmap --version | head -1 \
    && fping -v 2>&1 | head -1 \
    && nuclei -version 2>&1 | head -1 \
    && naabu -version 2>&1 | head -1 \
    && masscan --version 2>&1 | head -1 \
    && wireghost --version

ENTRYPOINT ["wireghost"]
