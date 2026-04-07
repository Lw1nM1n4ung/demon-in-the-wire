FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping curl unzip && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Install httpx
RUN HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v') \
    && curl -sL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin/ httpx \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir .

ENTRYPOINT ["wireghost"]
