#!/bin/sh
# fetch_release.sh <repo> <asset-name-pattern> <output-path> [unzip-target]
#
# Download a GitHub release asset, retrying the whole step on transient
# network failures.
#
# Two failure modes were seen against github.com from container networks:
#   1. curl exit 35 (TLS connection reset) on the release-asset CDN
#   2. DNS returning only a GitHub edge IP that is unreachable from the
#      container network (the host resolves a different, working edge)
#
# The second case defeats plain retries: every attempt resolves the same
# dead IP. So the candidate IPs are collected from several resolvers and
# each is tried in turn via curl --resolve, falling back to normal
# resolution. The metadata lookup runs inside $(...) in a pipeline, so
# under `set -e` / `set -o pipefail` a single transient failure would
# abort the whole build step; the entire fetch is therefore retried here.
#
# Usage:
#   fetch_release.sh projectdiscovery/nuclei linux_amd64.zip /tmp/nuclei.zip nuclei
#
# When an unzip target is given, that member is extracted next to the
# download (in /tools) and the extracted file is made executable.

set -e

REPO="$1"
PATTERN="$2"
OUT="$3"
UNZIP_TARGET="${4:-}"

attempt=1
max_attempts="${FETCH_RELEASE_MAX_ATTEMPTS:-10}"

# Collect candidate IPs for github.com from the system resolver plus a
# couple of public resolvers, so a dead edge from one resolver does not
# doom the fetch.
candidate_ips() {
  {
    getent ahostsv4 github.com 2>/dev/null | awk '{print $1}'
    for resolver in 1.1.1.1 8.8.8.8; do
      dig +short +time=3 +tries=1 "@${resolver}" github.com 2>/dev/null |
        grep -E '^[0-9]+\.'
    done
  } 2>/dev/null | sort -u
}

# Download $1 (a URL) to $2, trying each candidate GitHub IP in turn.
# The first hop is pinned via --resolve; redirects are followed normally.
download() {
  _url="$1"
  _dest="$2"
  _ips=$(candidate_ips)
  for _ip in $_ips; do
    if curl -sSfL --retry 2 --retry-all-errors --retry-delay 2 \
            --resolve "github.com:443:${_ip}" -o "$_dest" "$_url" 2>/dev/null; then
      return 0
    fi
  done
  # Fall back to the container's own resolver.
  curl -sSfL --retry 3 --retry-all-errors --retry-delay 3 -o "$_dest" "$_url"
}

while [ "$attempt" -le "$max_attempts" ]; do
  URL=$(curl -sSfL --retry 3 --retry-all-errors --retry-delay 3 \
          "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -o "\"browser_download_url\": *\"[^\"]*${PATTERN}\"" \
        | head -1 | cut -d'"' -f4) || true

  if [ -n "$URL" ] && download "$URL" "$OUT"; then
    if [ -n "$UNZIP_TARGET" ]; then
      # Zip-packaged asset: extract the member into /tools.
      unzip -o "$OUT" "$UNZIP_TARGET" -d /tools/
      chmod 0755 "/tools/${UNZIP_TARGET}"
    else
      # Raw binary asset: the download already is the executable.
      chmod 0755 "$OUT"
    fi
    exit 0
  fi

  echo "fetch_release: attempt ${attempt} for ${REPO} failed, retrying" >&2
  attempt=$((attempt + 1))
  sleep 5
done

echo "fetch_release: giving up on ${REPO}" >&2
exit 1
