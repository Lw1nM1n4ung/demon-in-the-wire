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

# ── Stage 2: Metasploit Framework (official upstream image) ──
# The framework is copied out of the official image rather than built from
# source: it ships a complete, current module tree plus the exact gem set
# the framework was tested against.
#
# That image is Alpine (musl libc); this one is Debian (glibc).  The Ruby
# runtime and the gems are therefore relocated under /opt/msf and run
# through musl's loader explicitly — see msfconsole-wrapper.sh.
FROM metasploitframework/metasploit-framework:latest AS msf

# ── Stage 3: final image ──
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
    samba-common-bin smbclient \
    ruby ruby-dev build-essential libcurl4 \
    && rm -rf /var/lib/apt/lists/*

# enum4linux — Debian has no package; the classic perl script is what
# parsers/enum4linux.py expects (enum4linux-ng emits a different format).
RUN curl -fsSL -o /usr/local/bin/enum4linux \
        https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl \
    && chmod +x /usr/local/bin/enum4linux \
    && perl -c /usr/local/bin/enum4linux >/dev/null 2>&1

# searchsploit (exploitdb) — shallow clone to keep image size reasonable.
RUN for i in 1 2 3 4 5; do \
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && break || \
        { echo "exploitdb clone attempt $i failed, retrying"; rm -rf /opt/exploitdb; sleep 10; }; \
    done \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Metasploit module metadata — the JSON index the exploit matcher
# (scanner/msf_matcher.py) reads to match scanned ports/findings against
# known modules.  Without this file the matcher logs "exploit matching
# disabled" and every scan stores zero ExploitMatch rows, which leaves the
# /exploits page empty.  Only the metadata is needed for matching — the
# full framework (msfconsole) is not required for detection.
RUN mkdir -p /opt/metasploit-framework/embedded/framework/db \
    && for i in 1 2 3 4 5; do \
        curl -sSfL --retry 3 --retry-all-errors --retry-delay 3 \
            "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json" \
            -o /opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json && break || \
        { echo "MSF metadata download attempt $i failed, retrying"; \
          rm -f /opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json; sleep 10; }; \
    done \
    && test -s /opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json \
    && python3 -c "import json,sys; d=json.load(open('/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json')); print('MSF modules:', len(d)); sys.exit(0 if len(d) > 1000 else 1)"

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

# ── Metasploit Framework ────────────────────────────────────────────────
# Relocated out of the official Alpine image.  The musl loader and the
# Alpine shared libraries go into a private prefix so the Debian system's
# own (glibc) libraries are untouched; Ruby's stdlib and libruby stay at
# /usr/local/lib because the Ruby binary has that path compiled in.
COPY --from=msf /usr/src/metasploit-framework /opt/msf/framework
COPY --from=msf /usr/local/bundle /opt/msf/bundle
COPY --from=msf /usr/local/lib/ruby /usr/local/lib/ruby
COPY --from=msf /usr/local/lib/libruby.so* /usr/local/lib/
COPY --from=msf /usr/local/bin/ruby /opt/msf/ruby/bin/ruby
COPY --from=msf /lib/ld-musl-x86_64.so.1 /opt/msf/alpine/lib/ld-musl-x86_64.so.1
COPY --from=msf /usr/lib/*.so* /opt/msf/alpine/usr/lib/

# The launcher the worker invokes.
COPY web_portal/msfconsole-wrapper.sh /usr/local/bin/msfconsole
RUN chmod 0755 /usr/local/bin/msfconsole

# Prove at build time that the relocated framework actually runs — a
# silently broken msfconsole would only surface as a failed exploit.
RUN set -e; \
    test -f /opt/msf/framework/msfconsole; \
    test -d /opt/msf/framework/modules; \
    test -s /opt/msf/framework/db/modules_metadata_base.json; \
    timeout 300 msfconsole -q -x 'version; exit' 2>&1 | tee /tmp/msf-version.txt; \
    grep -q '^Framework:' /tmp/msf-version.txt; \
    rm -f /tmp/msf-version.txt; \
    echo "MSF module tree: $(find /opt/msf/framework/modules -name '*.rb' | wc -l) module(s)"

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
