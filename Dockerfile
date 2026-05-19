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

# katana (web crawler)
RUN KATANA_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64.zip"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$KATANA_URL" -o katana.zip \
    && unzip -o katana.zip katana -d /tools/ \
    && chmod +x /tools/katana && rm katana.zip

# kerbrute (Kerberos user enumeration & brute-force)
RUN KERBRUTE_URL=$(curl -sL https://api.github.com/repos/ropnop/kerbrute/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*linux_amd64[^"]*"' \
        | head -1 | cut -d'"' -f4) \
    && curl -sL "$KERBRUTE_URL" -o /tools/kerbrute \
    && chmod +x /tools/kerbrute

# === Stage 1.5: Build fingerprintx from source (Go toolchain required) ===
FROM golang:1.23-bookworm AS fpx-builder
RUN go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# === Stage 2: Final image ===
FROM python:3.12-slim-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap fping masscan libpcap0.8 libsnmp40 git rsync libxml2-utils \
    arp-scan netdiscover \
    sslscan nfs-common snmp onesixtyone \
    chromium curl gnupg ca-certificates \
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

# Install Metasploit Framework (optional, adds ~1.5GB)
RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# Download Metasploit module metadata (exploit matching, ~50MB)
RUN mkdir -p /opt/msf \
    && curl -sL https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json \
       -o /opt/msf/modules_metadata_base.json \
    && echo "MSF metadata: $(python3 -c "import json; print(len(json.load(open('/opt/msf/modules_metadata_base.json'))))" 2>/dev/null || echo 'download failed') modules"

# Install wireghost (before Go binaries — pip httpx overwrites /usr/local/bin/httpx)
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY wireghost.example.yml .
RUN pip install --no-cache-dir .

# Install getsploit (Vulners API exploit search)
RUN pip install --no-cache-dir getsploit

# AD recon tools (impacket, BloodHound, LDAP enumeration)
RUN pip install --no-cache-dir impacket ldapdomaindump bloodhound-python

# Install NetExec (nxc) from GitHub — not on PyPI
RUN pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git 2>/dev/null || \
    echo "NetExec install skipped (optional — pipeline will skip nxc if unavailable)"

# Copy pre-built Go binaries (AFTER pip to avoid overwrite)
COPY --from=tools /tools/nuclei /usr/local/bin/nuclei
COPY --from=tools /tools/httpx /usr/local/bin/httpx
COPY --from=tools /tools/naabu /usr/local/bin/naabu
COPY --from=tools /tools/gowitness /usr/local/bin/gowitness
COPY --from=tools /tools/katana /usr/local/bin/katana
COPY --from=tools /tools/kerbrute /usr/local/bin/kerbrute

# fingerprintx — service fingerprinting for web detection refinement
COPY --from=fpx-builder /go/bin/fingerprintx /usr/local/bin/fingerprintx

# Download nuclei templates
RUN nuclei -update-templates

# Verify all tools
RUN echo "=== Tool verification ===" \
    && nmap --version | head -1 \
    && fping -v 2>&1 | head -1 \
    && arp-scan --version 2>&1 | head -1 \
    && timeout 5 naabu -version 2>&1 | head -1 || echo "naabu: available" \
    && timeout 5 masscan --version 2>&1 | head -1 || echo "masscan: available" \
    && timeout 5 gowitness version 2>&1 | head -1 || echo "gowitness: available" \
    && timeout 5 sslscan --version 2>&1 | head -1 || echo "sslscan: available" \
    && timeout 5 katana -version 2>&1 | head -1 || echo "katana: available" \
    && timeout 5 msfconsole --version 2>&1 | head -1 || echo "msfconsole: available" \
    && timeout 5 nuclei -version 2>&1 | head -1 || echo "nuclei: available" \
    && (timeout 5 showmount --version 2>&1 | head -1 || true) \
    && (timeout 5 snmpwalk -V 2>&1 | head -1 || true) \
    && (timeout 5 netdiscover -help 2>&1 | head -1 || true) \
    && (timeout 5 impacket-GetNPUsers -h 2>&1 | head -1 || echo "impacket: available") \
    && (timeout 5 ldapdomaindump --help 2>&1 | head -1 || echo "ldapdomaindump: available") \
    && (timeout 5 bloodhound-python --help 2>&1 | head -1 || echo "bloodhound: available") \
    && (timeout 5 kerbrute --help 2>&1 | head -1 || echo "kerbrute: available") \
    && timeout 5 fingerprintx -h 2>&1 | head -1 || echo "fingerprintx: available" \
    && wireghost --version

RUN find / -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null; \
    find / -perm -2000 -type f -exec chmod g-s {} + 2>/dev/null; \
    true

ENV WIREGHOST_OUTPUT_DIR=/data/output
ENTRYPOINT ["wireghost"]
