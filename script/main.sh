#!/bin/bash
# ~/.script/nmap_live_nettacker_loop.sh
# Usage: ./nmap_live_nettacker_loop.sh 192.168.1.0/24

# --- ANSI Color Definitions ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Custom Log Function ---
log_echo() {
    local color="$1"
    local label="$2"
    local message="$3"
    local timestamp=$(date +"%Y-%m-%d %I:%M%p")
    echo -e "${color}${timestamp} [${label}] ${message}${NC}"
}

# --- Logging Setup ---
LOG_FILE="/root/output/nmap_scan_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
log_echo "$CYAN" "SETUP" "===================================================="
log_echo "$CYAN" "SETUP" " ALL-IN-ONE PARALLEL PIPELINE (Nmap+Nuclei+Nettacker) "
log_echo "$CYAN" "SETUP" "===================================================="
log_echo "$YELLOW" "LOG" "Logging all output to: ${LOG_FILE}"
echo ""

# --- Initialization ---
log_echo "$BLUE" "SETUP" "Activating Python environment and cleaning old output..."
source /root/.script/docx/env/bin/activate
source /root/.bashrc
rm -rf /root/output/*
log_echo "$GREEN" "SETUP" "Environment setup complete."

# --- Arguments ---
if [ -z "$1" ]; then
    log_echo "$RED" "ERROR" "No target provided. Usage: $0 192.168.1.0/24"
    exit 1
fi

export target="$1"
export target_dir=$(echo "$target" | cut -d"/" -f1)

export livehost_dir="/root/output/$target_dir/all/live_host"
export livehost="$livehost_dir/live.txt"
export web="/root/output/$target_dir/all/web/web.txt"
export livehost_nmap_output="/root/output/$target_dir/all/live_host/live.nmap"
export ip_dir="/root/output/$target_dir/ip"

log_echo "$YELLOW" "TARGET" "Target set to: ${target}"
log_echo "$YELLOW" "OUTPUT" "Output Base Directory: /root/output/${target_dir}"

# --- Ensure directories exist ---
log_echo "$BLUE" "DIR" "Creating core directory structure..."
mkdir -p "$livehost_dir"
mkdir -p "/root/output/$target_dir/all/web"
mkdir -p "$ip_dir"

# ----------------------------------------
## PHASE 1: Live Host Discovery (UNCHANGED)
# ----------------------------------------
echo -e "\n${CYAN}----------------------------------------------------${NC}"
log_echo "$CYAN" "PHASE" "PHASE 1: Live Host Discovery (Nmap Ping Scan & Fping)"
echo -e "${CYAN}----------------------------------------------------${NC}"

log_echo "$YELLOW" "NMAP" "Starting Nmap ping scan for live hosts on ${target}...${NC}"
nmap -sn "$target" -oN "$livehost_nmap_output"

log_echo "$BLUE" "FILE" "Extracting unique live IP addresses and hostnames..."
: > "$livehost_dir"/nmap.txt
: > "$livehost"

grep "Nmap scan report for" "$livehost_nmap_output" | cut -d" " -f5 > "$livehost_dir"/nmap.txt || true
grep "Nmap scan report for" "$livehost_nmap_output" | grep "(" | cut -d"(" -f2 | cut -d ")" -f1 >> "$livehost_dir"/nmap.txt || true

log_echo "$YELLOW" "FPING" "Running fping to identify additional live hosts..."
fping -a -g "$target" > "$livehost_dir"/fping.txt 2>/dev/null

log_echo "$BLUE" "AGGR" "Merging Nmap and fping results, sorting, and saving to ${livehost}..."
cat "$livehost_dir"/nmap.txt "$livehost_dir"/fping.txt | \
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | \
    sort -u | sort -V \
    > "$livehost"

LIVE_HOST_COUNT=$(wc -l < "$livehost")
log_echo "$GREEN" "NMAP" "Found ${LIVE_HOST_COUNT} live IP addresses after merging."

log_echo "$BLUE" "DIR" "Creating per-IP directory structure for ${LIVE_HOST_COUNT} hosts..."
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | while IFS= read -r ip; do
    mkdir -p "$ip_dir/$ip/nmap/docx" "$ip_dir/$ip/nmap/xml" "$ip_dir/$ip/web/nuclei" "$ip_dir/$ip/web/dirsearch" "$ip_dir/$ip/vuln/nettacker" /root/output/"$target_dir"/final_reports/ports_xlsx /root/output/"$target_dir"/final_reports/summary_vuln_report
done

log_echo "$BLUE" "FILE" "Clearing/Initializing aggregated web target list: ${web}"
: > "$web"

# ----------------------------------------
## PHASE 2: MASTER PIPELINE (Nmap + Nuclei + Nettacker + Report)
# ----------------------------------------

echo -e "\n${CYAN}----------------------------------------------------${NC}"
log_echo "$CYAN" "PHASE" "PHASE 2: Master Pipeline (All Tools Combined)"
log_echo "$YELLOW" "INFO" "Scanning, Nuclei, Nettacker, and Reporting per IP in parallel."
echo -e "${CYAN}----------------------------------------------------${NC}"

# Export variables so the xargs subshell can read them
export ip_dir target_dir livehost_nmap_output web

grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | \
    sort -u | \
    xargs -P10 -I {} sh -c '
        set -e
        ip="{}"
        
        # --- Subshell Variables & Colors ---
        TIMESTAMP=$(date +"%Y-%m-%d %I:%M%p")
        GREEN="\033[0;32m"
        BLUE="\033[0;34m"
        YELLOW="\033[1;33m"
        NC="\033[0m"

        # Define paths
        base="$ip_dir/$ip"
        out="$base/nmap/xml/nmap_port_scan_$ip"
        DOCX_DIR="$base/nmap/docx"
        TEMP_WEB_FILE="/root/output/tmp/python_web$ip.txt"
        XML="$base/nmap/xml/nmap_port_scan_$ip.xml"
        NET_DIR="$base/vuln/nettacker"

        # ===================================================
        # [STEP 1] Nmap Port Scan & Processing
        # ===================================================
        
        echo -e "\n${GREEN}${TIMESTAMP} [NMAP] -> Scanning IP: $ip ${NC}"
        nmap --open -p- -Pn -oA "$out" "$ip"

        echo -e "    ${BLUE}${TIMESTAMP} [DOCX] [+] Generating docx report for $ip...${NC}"
        python3 /root/.script/docx/xml_to_docx.py "$XML" "$DOCX_DIR"

        echo -e "    ${BLUE}${TIMESTAMP} [SHEET] [+] Running sheet.py...${NC}"
        mkdir -p "$base/vuln" "/root/output/$target_dir/all/nmap/command/" "/root/output/tmp"
        python3 /root/.script/docx/sheet.py "$XML" > "$DOCX_DIR/report.txt"

        # Web Finder (Generate URLs)
        echo -e "    ${BLUE}${TIMESTAMP} [WEB] [+] Running web_finder.py using $XML...${NC}"
        python3 /root/.script/docx/web_finder.py "$XML" "$TEMP_WEB_FILE"
        
        # Append to main web list for backup
        cat "$TEMP_WEB_FILE" >> "$web" 2>/dev/null || true

        # ===================================================
        # [STEP 2] Nuclei Scan (INTEGRATED HERE)
        # ===================================================
        
        if [ -s "$TEMP_WEB_FILE" ]; then
            echo -e "    ${YELLOW}${TIMESTAMP} [NUCLEI] -> Found web ports. Running Nuclei for $ip...${NC}"
            
            # Iterate over URLs found for THIS specific host
            cat "$TEMP_WEB_FILE" | while read url; do
                [ -z "$url" ] && continue

                # Your original Nuclei path logic
                fn=$(echo "$url" | sed -E "s~https?://~~Ig" | tr "/:?=&" "____" | tr -s "_")
                # Since we are inside the IP loop, we force output to this IP directory
                # to ensure the reporter finds it later.
                OUTPUT_DIR="$base/web/nuclei"
                mkdir -p "$OUTPUT_DIR"

                echo -e "      ${BLUE}${TIMESTAMP} [NUCLEI] Scanning $url ...${NC}"
                
                # Running Nuclei with your exact arguments
                # NOTE: We force the json filename to match what end.py expects: nuclei_scan_${ip}.json
                nuclei -u "$url" -s critical,high,medium,low,info \
                    -o "$OUTPUT_DIR/nuclei_scan_${fn}.txt" \
                    -json-export "$OUTPUT_DIR/nuclei_scan_${ip}.json" >/dev/null 2>&1 || true
            done
        fi

        # ===================================================
        # [STEP 3] Nmap Vulnerability Commands
        # ===================================================
        echo -e "    ${BLUE}${TIMESTAMP} [NMAP] [+] Executing Nmap parser for vulnerability commands on $ip...${NC}"
        python3 /root/.script/docx/nmap_parser.py "$XML" >> /root/output/"$target_dir"/all/nmap/command/commands_"$ip"_.sh

        echo -e "    ${BLUE}${TIMESTAMP} [BASH] [+] Running vulnerability scans...${NC}"
        sort -u /root/output/"$target_dir"/all/nmap/command/commands_"$ip"_.sh | bash

        # Cleanup & XLSX
        echo -e "    ${BLUE}${TIMESTAMP} [FILE] [+] Moving temporary files for $ip...${NC}"
        mv /root/output/tmp/nmap_vuln_scan_"$ip".nmap "$base"/vuln/ 2>/dev/null || true
        mv "$TEMP_WEB_FILE" "$base"/web/ 2>/dev/null || true
        mv /root/output/tmp/nmap_vuln_scan_"$ip".gnmap "$base"/vuln/ 2>/dev/null || true
        mv /root/output/tmp/nmap_vuln_scan_"$ip".xml "$base"/vuln/ 2>/dev/null || true

        echo -e "    ${BLUE}${TIMESTAMP} [XLSX] [+] Generating XLSX ports summary for $ip...${NC}"
        python3 /root/.script/docx/xml_to_xlsx.py -i "$XML" -o /root/output/"$target_dir"/final_reports/ports_xlsx/xlsx_"$ip".xlsx

        # ===================================================
        # [STEP 4] Nettacker Scan
        # ===================================================
        
#        echo -e "    ${YELLOW}${TIMESTAMP} [NETTK] -> Scanning IP: $ip ${NC}"
#        nettacker -i "$ip" --profile all --exclude *_brute,dir_scan,*_brutes -o "$NET_DIR/nettacker_scan_$ip.html" --timeout 60 || true

        # ===================================================
        # [STEP 5] Final Report
        # ===================================================
        
        nfile="$base/nmap/xml/nmap_port_scan_$ip.xml"
        vfile="$base/vuln/nmap_vuln_scan_$ip.xml"
        jfile="$base/web/nuclei/nuclei_scan_${ip}.json"
        outfile="$base/endpoint_report_$ip.docx"

        # Now jfile (Nuclei) might actually exist because we ran Step 2!
        if [[ -f "$nfile" || ( -f "$vfile" && -s "$vfile" ) || ( -n "$jfile" && -s "$jfile" ) ]]; then
             echo -e "    ${GREEN}${TIMESTAMP} [REPORT] Processing $ip - creating final report...${NC}"
             python /root/.script/docx/end.py -n "$nfile" -v "$vfile" -j "$jfile" -o "$outfile"

             echo -e "    ${BLUE}${TIMESTAMP} [FILE] Copying report to final_reports...${NC}"
             cp "$outfile" /root/output/"$target_dir"/final_reports/summary_vuln_report
        else
             echo -e "    ${YELLOW}${TIMESTAMP} [REPORT] Skipping report for $ip (missing files).${NC}"
        fi
    '

# ----------------------------------------
## PHASE 5: Consolidation (UNCHANGED)
# ----------------------------------------

echo -e "\n${CYAN}----------------------------------------------------${NC}"
log_echo "$CYAN" "PHASE" "PHASE 3: File and Directory Consolidation (Fallback Cleanup)"
echo -e "${CYAN}----------------------------------------------------${NC}"

log_echo "$YELLOW" "CLEANUP" "Searching for and consolidating directories..."

find "$ip_dir" -maxdepth 1 -type d -name '*_*' | while IFS= read -r suffixed_dir; do
    BASE_NAME=$(basename "$suffixed_dir" | cut -d'_' -f1)
    TARGET_DIR="$ip_dir/$BASE_NAME"

    if [ -d "$TARGET_DIR" ]; then
        log_echo "$BLUE" "MOVE" "Consolidating contents of $(basename "$suffixed_dir") into $BASE_NAME..."
        mv "$suffixed_dir"/* "$TARGET_DIR"/ 2>/dev/null
        rmdir "$suffixed_dir" 2>/dev/null || true
    else
        true
    fi
done

log_echo "$GREEN" "CLEANUP" "Directory consolidation complete."

# ----------------------------------------
## Cleanup & Exit
# ----------------------------------------

echo -e "\n${CYAN}----------------------------------------------------${NC}"
log_echo "$GREEN" "FINISH" "Script finished successfully! All output saved."
echo -e "${CYAN}----------------------------------------------------${NC}"

stty echo || true
exit 0
