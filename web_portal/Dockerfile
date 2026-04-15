FROM python:3.12-slim

WORKDIR /app

# System deps for MySQL client
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc default-libmysqlclient-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

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

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
