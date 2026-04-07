#!/bin/bash

# --- Initialization and Environment Setup ---
source /root/.script/docx/env/bin/activate
source /root/.bashrc

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Variable Definitions ---
export target="$1"
# Extract the base directory name from the target (e.g., "192.168.1.0/24" becomes "192.168.1.0")
export target_dir=$(echo "$target" | cut -d"/" -f1)

export livehost_dir="/root/output/$target_dir/all/live_host"
export livehost="$livehost_dir/live.txt"
export web="/root/output/$target_dir/all/web/web.txt"
export livehost_nmap_output="/root/output/$target_dir/all/live_host/live.nmap"
export ip_dir="/root/output/$target_dir/ip"

# --- Directory Creation ---
mkdir -p "$livehost_dir" 
mkdir -p "/root/output/$target_dir/all/web"
mkdir -p "$ip_dir"

# --- Nmap Live Host Scan (Ping Scan) ---
echo "Starting Nmap ping scan for live hosts on $target..."
# -sn: Ping scan (no port scan)
# -oN: Output normal
###################################
nmap -sn "$target" -oN "$livehost_nmap_output"

# --- Extract Live IPs and Hostnames ---
echo "Extracting live IP addresses..."
# Clear the file first for clean extraction
 > "$livehost"
# 1. Extract hostnames (if available) - assumes the format 'Nmap scan report for <hostname>'


grep "Nmap scan report for" "$livehost_nmap_output" | cut -d" " -f5 > "$livehost"
cat $livehost
# 2. Extract IP addresses (if available) - assumes the format 'Nmap scan report for <hostname> (<IP>)'
grep "Nmap scan report for" "$livehost_nmap_output" | \
    grep "(" | \
    cut -d"(" -f2 | \
    cut -d ")" -f1 >> "$livehost"

# Clean up and normalize the list of potential targets
sort -u "$livehost" -o "$livehost"

# --- Directory and Web Target Setup Loop ---
echo "Setting up output directories and initial web targets for each live IP..."
# Filter for only valid IP addresses to create main IP directories
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | while IFS= read -r ip; do
    # Create the necessary subdirectories for each IP
    mkdir -p "$ip_dir"/"$ip"/nmap/docx "$ip_dir"/"$ip"/nmap/xml "$ip_dir"/"$ip"/web/nuclei  "$ip_dir"/"$ip"/web/dirsearch

    # Identify potential web targets for the IP and save them
    # The original script uses a redundant cat/httpx inside the loop,
    # which is inefficient as 'httpx' should only process actual URLs.
    # The original logic of 'cat live.txt | httpx' and saving the output
    # to a file named after the specific IP directory is logically flawed
    # since 'live.txt' contains *all* live targets.
    # We'll use the IP itself as a potential web target and rely on subsequent
    # full port scan/service detection for a better list.
    # For now, we'll keep the IP in its own 'web.txt' for consistency with
    # the original script's subsequent steps, although this list will be incomplete.
    #echo "$ip" | httpx | sort -u > "$ip_dir/$ip/web/web.txt"
done
ip=$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost")
 #echo $ip | xargs -P100 -I {} sh -c 'echo "now start : {}" ;  echo {} |  httpx  > "$ip_dir/{}/web/web.txt"'
# Export the necessary variable so the sub-shell (sh -c) can see it
export ip_dir

# 1. Pipe the list of IPs directly into xargs instead of storing them in a single variable.
# This handles large lists safely.
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost"  | sort -u | httpx > /root/output/"$target_dir"/all/web/web.txt

# --- Full Nmap Port Scan and Documentation Generation ---
echo "Starting Nmap full port scans and report generation..."
# Filter 'live.txt' to only include valid IP addresses for the port scan
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$livehost" | \
    sort -u | \
    # xargs for parallel execution (P200 is very aggressive)
    # The commands are grouped and executed sequentially for each IP by 'sh -c'
    xargs -P200 -I {} sh -c '
        # Nmap Full Port Scan: -p- (all ports), -Pn (treat all hosts as online), -oX (XML output)
        nmap --open -p- -Pn -oX "$ip_dir"/{}/nmap/xml/nmap_port_scan_{}.xml {}
        
        # XML to DOCX conversion
        python3 /root/.script/docx/xml_to_docx.py "$ip_dir"/{}/nmap/xml/nmap_port_scan_{}.xml "$ip_dir"/{}/nmap/docx
        
        # Generate port scan report text
        mkdir -p "$ip_dir"/{}/vuln /root/output/"$target_dir"/all/nmap/command/ /root/output/tmp
        python3 /root/.script/docx/sheet.py "$ip_dir"/{}/nmap/xml/nmap_port_scan_{}.xml > "$ip_dir"/{}/nmap/docx/report.txt
       

       python3 /root/.script/docx/nmap_parser.py "$ip_dir"/{}/nmap/xml/nmap_port_scan_{}.xml >> /root/output/"$target_dir"/all/nmap/command/commands_{}_.sh
       echo "/root/output/$target_dir/all/nmap/command/commands_{}_.sh"
       cat /root/output/"$target_dir"/all/nmap/command/commands_{}_.sh
       cat /root/output/"$target_dir"/all/nmap/command/commands_{}_.sh | sort -u | bash
       mv /root/output/tmp/nmap_vuln_scan_{}* "$ip_dir"/{}/vuln/
'

# --- Nuclei Vulnerability Scan ---
echo "Starting Nuclei vulnerability scans on identified web targets..."
cat "$web"
# 1. Concatenate all 'web.txt' files from all IP directories
# 2. Re-run httpx to ensure all targets are clean and alive (optional but safe)
# 3. Use xargs to execute nuclei in parallel (P5)
cat "$web" | \
    xargs -P5 -I {} sh -c '
        # Create a safe filename (fn) from the URL by removing scheme and replacing delimiters
                fn=$( echo {} | sed -E 's~https?://~~Ig');        
        nuclei -u {} -s critical,high,medium,low,info -o "$ip_dir"/${fn}/web/nuclei/nuclei_scan_${fn}.txt -json-export "$ip_dir"/${fn}/web/nuclei/nuclei_scan_${fn}.json
'

while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue
  base="$HOME/output/192.168.1.12/ip/$ip"
  nfile="$base/nmap/xml/nmap_port_scan_$ip.xml"
  vfile="$base/vuln/nmap_vuln_scan_$ip.xml"
  jfile="$base/web/nuclei/nuclei_scan_${fn}.json"
  outfile="$base/endpoint_report_$ip.docx"

  if [[ -f "$nfile" || -f "$vfile" ]]; then
    echo "Processing $ip ..."
    python /root/.script/docx/end.py -n "$nfile" -v "$vfile" -j "$jfile" -o "$outfile"
  else
    echo "Skipping $ip — missing files in $base"
  fi
done < ips.txt

#---
# --- Dirsearch Web Content Discovery ---
# --- Cleanup and Exit ---
# Restore terminal echo (in case it was disabled before execution)
stty echo
echo "Script finished successfully."
exit
