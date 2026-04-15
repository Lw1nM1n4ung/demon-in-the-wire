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

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src

EXPOSE 8000
