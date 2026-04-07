#!/bin/bash
# nmap_live.sh - improved and safer version

# --- Initialization and Environment Setup ---
source /root/.script/docx/env/bin/activate
source /root/.bashrc

# Exit immediately if a command exits with a non-zero status.
set -e
set -o pipefail

# --- Variable Definitions ---
export target="$1"
if [[ -z "$target" ]]; then
  echo "Usage: $0 <target>   e.g. 192.168.1.0/24"
  exit 2
fi

# Extract the base directory name from the target (e.g., "192.168.1.0/24" -> "192.168.1.0")
export target_dir=$(echo "$target" | cut -d"/" -f1)

export livehost_dir="/root/output/$target_dir/all/live_host"
export livehost="$livehost_dir/live.txt"
export web="/root/output/$target_dir/all/web/web.txt"
export livehost_nmap_output="/root/output/$target_dir/all/live_host/live.nmap"
export ip_dir="/root/output/$target_dir/ip"

# Parallelism controls (tune as needed)
NMAP_PARALLEL=50    # used indirectly by xargs for full nmap scans (was 200)
DIRSEARCH_PARALLEL=5
NUCLEI_PARALLEL=5

# --- Directory Creation ---
mkdir -p "$livehost_dir"
mkdir -p "/root/output/$target_dir/all/web"
mkdir -p "$ip_dir"

# --- Nmap Live Host Scan (Ping Scan) ---
echo "Starting Nmap ping scan for live hosts on $target..."
# -sn: Ping scan (no port scan)
# -oN: Output normal
nmap -sn "$target" -oN "$livehost_nmap_output"

# --- Extract Live IPs and Hostnames ---
echo "Extracting live IP addresses..."
> "$livehost"

# Best-effort robust parsing:
# Nmap prints either:
# - "Nmap scan report for 1.2.3.4"
# - "Nmap scan report for hostname (1.2.3.4)"
# We want to capture both hostname and IP (but primarily IPs).
# Prefer to capture IPs for later use.
# Use awk to handle both variants.
awk '
/Nmap scan report for/ {
  # If line contains "(", extract the ip inside parentheses
  if (match($0, /\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)/, m)) {
    print m[1];
  } else {
    # No parentheses, last field is either an IP or a hostname; print it
    print $NF;
  }
}
' "$livehost_nmap_output" >> "$livehost"

# Normalize unique list
sort -u "$livehost" -o "$livehost"
cat "$livehost"

# --- Directory and Web Target Setup Loop ---
echo "Setting up per-IP directories..."
# Create per-IP directories for valid IPv4 addresses only
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | sort -u | while IFS= read -r ip; do
    mkdir -p "$ip_dir/$ip/nmap/docx" "$ip_dir/$ip/nmap/xml" "$ip_dir/$ip/web/nuclei" "$ip_dir/$ip/web/dirsearch"
    # Add the bare IP as a web target as a starting point (httpx will probe it)
    printf "http://%s\nhttps://%s\n" "$ip" "$ip" >> "$ip_dir/$ip/web/web.txt"
done

# Consolidate all web targets previously discovered (also include any created above)
# Use sort -u to avoid duplicates.
find "$ip_dir" -type f -name "web.txt" -exec cat {} + 2>/dev/null | sort -u > "$web" || true

# In case there were no per-IP files, ensure $web exists (could be empty)
: > "$web"

# --- Full Nmap Port Scan and Documentation Generation ---
echo "Starting Nmap full port scans and report generation..."
# Use grep'ed IP list and xargs to parallelize. Be careful with too-high parallelism.
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | sort -u | \
  xargs -P"$NMAP_PARALLEL" -n1 -I {} sh -c '
    set -e
    ip="$1"
    ip_dir="$2"

    mkdir -p "$ip_dir/$ip/nmap/xml" "$ip_dir/$ip/nmap/docx"
    echo "Scanning all ports for $ip ..."
    nmap --open -p- -Pn -oX "$ip_dir/$ip/nmap/xml/nmap_port_scan_${ip}.xml" "$ip"

    echo "Converting XML to DOCX for $ip ..."
    python3 /root/.script/docx/xml_to_docx.py "$ip_dir/$ip/nmap/xml/nmap_port_scan_${ip}.xml" "$ip_dir/$ip/nmap/docx"

    echo "Generating textual report for $ip ..."
    python3 /root/.script/docx/sheet.py "$ip_dir/$ip/nmap/xml/nmap_port_scan_${ip}.xml" > "$ip_dir/$ip/nmap/docx/report.txt"
  ' _ {} "$ip_dir"

# --- Nuclei Vulnerability Scan ---
echo "Starting Nuclei vulnerability scans on identified web targets..."
# Read each URL from consolidated web list, run nuclei in parallel.
# Use a safe filename (strip scheme only, then sanitize).
cat "$web" | sort -u | xargs -P"$NUCLEI_PARALLEL" -n1 -I {} sh -c '
  set -e
  url="$1"
  ip_dir="$2"

  # create safe filename: remove leading protocol only, keep rest intact
  fn=$(printf "%s" "$url" | sed -E "s~^https?://~~I" | sed -E "s#[/:]+#_#g; s/[^A-Za-z0-9._-]/_/g" | sed -E "s/^_+//; s/_+$//" | cut -c1-200)
  outdir="$ip_dir/$fn/web/nuclei"
  mkdir -p "$outdir"
  echo "Nuclei -> $url -> $outdir/nuclei_scan_${fn}.txt"
  nuclei -u "$url" -s critical,high,medium,low,info -o "$outdir/nuclei_scan_${fn}.txt" || echo "nuclei failed for $url"
' _ {} "$ip_dir"

# --- Dirsearch Web Content Discovery ---
echo "Starting Dirsearch web content discovery scans..."
cat "$web" | sort -u | httpx -silent -o - | \
  xargs -P"$DIRSEARCH_PARALLEL" -n1 -I {} sh -c '
    set -e
    url="$1"
    ip_dir="$2"

    # create safe filename for URL (strip scheme only)
    fn=$(printf "%s" "$url" | sed -E "s#^https?://##I" | sed -E "s#[/:]+#_#g; s/[^A-Za-z0-9._-]/_/g" | sed -E "s/^_+//; s/_+$//" | cut -c1-200)
    outdir="$ip_dir/$fn/web/dirsearch"
    mkdir -p "$outdir"

    echo "dirsearch -> $url -> $outdir/dirsearch_${fn}.txt"
    dirsearch -u "$url" \
      -w /root/.wordlist/combined_directories.txt \
      -e "$(tr "\n" "," < /root/.wordlist/all-extensionless.txt | sed "s/,$//")" \
      -f --overwrite-extensions \
      -r --deep-recursive --force-recursive -R 6 --recursion-status=200-399 \
      --crawl \
      --include-status=200,201,202,204,301-303,307,401,403 \
      --full-url \
      -t 10 \
      -o "$outdir/dirsearch_${fn}.txt" || echo "dirsearch failed for $url"
  ' _ {} "$ip_dir"

# --- Cleanup and Exit ---
stty echo || true
echo "Script finished successfully."
exit 0
