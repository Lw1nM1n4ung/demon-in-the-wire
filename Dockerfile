FROM python:3.12-slim

# System tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping curl wget git masscan && rm -rf /var/lib/apt/lists/*

# Install Go (for ProjectDiscovery tools)
ENV GO_VERSION=1.22.4
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install ProjectDiscovery tools via go install
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir .

ENTRYPOINT ["wireghost"]
