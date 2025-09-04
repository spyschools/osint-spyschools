#!/usr/bin/env bash
# OSINT Toolkit (Ethical Edition) — Bash utility for Linux with TXT/Markdown output

set -euo pipefail

err() { echo "[!] $*" >&2; }
info() { echo "[i] $*"; }
ok() { echo "[+] $*"; }

need() { command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; exit 1; }; }
need curl; need jq; need dig; need whois; need openssl

HLINE=$(printf '%*s\n' 80 '' | tr ' ' '-')
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
json_pretty() { jq -r '.' || cat; }

# Default output format
FORMAT="txt"
[[ "${1:-}" == "--md" ]] && { FORMAT="md"; shift; }

OUTFILE="osint_report_$(date +%Y%m%d_%H%M%S).$FORMAT"
log() { tee -a "$OUTFILE"; }

section() {
  if [[ "$FORMAT" == "md" ]]; then
    echo -e "\n## $1\n"
  else
    echo -e "\n=== $1 ==="
  fi
}

# --- Domain Intel ---
run_domain() {
  local domain="$1"
  {
    if [[ "$FORMAT" == "md" ]]; then echo "# Domain OSINT for: $domain ($(timestamp))"; else echo "$HLINE"; ok "Domain OSINT for: $domain (UTC: $(timestamp))"; echo "$HLINE"; fi

    [[ "$domain" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]] || { err "Invalid domain"; exit 1; }

    section "DNS Records (A/AAAA/MX/NS/TXT)"
    for rr in A AAAA MX NS TXT; do echo "-- $rr"; dig +short "$domain" $rr || true; echo; done

    section "WHOIS"; whois "$domain" | sed -n '1,200p' || true

    section "RDAP"; curl -fsSL "https://rdap.org/domain/$domain" | json_pretty || true

    section "Certificate Transparency (subdomains)"
    curl -fsSL "https://crt.sh/?q=%25.$domain&output=json" \
      | jq -r '.[].name_value' | sort -u | head -n 100 || echo "(none/rate-limited)"

    section "Wayback Machine Snapshots"
    curl -fsSL "https://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=timestamp,original&limit=5" \
      | jq -r '.[] | @tsv' || echo "(no snapshots)"

    section "Reverse DNS for A records"
    while read -r ip; do [[ -z "$ip" ]] && continue; echo "IP: $ip"; dig +short -x "$ip" || true; done < <(dig +short "$domain" A)

    section "HTTP Quick Check"; run_http "https://$domain" || true
  } | log
}

# --- IP Intel ---
run_ip() {
  local ip="$1"
  {
    if [[ "$FORMAT" == "md" ]]; then echo "# IP OSINT for: $ip ($(timestamp))"; else echo "$HLINE"; ok "IP OSINT for: $ip (UTC: $(timestamp))"; echo "$HLINE"; fi

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([A-Fa-f0-9:]+)$ ]] || { err "Invalid IP"; exit 1; }

    section "WHOIS"; whois "$ip" | sed -n '1,200p' || true
    section "Geo/ASN (ip-api.com)"; curl -fsSL "http://ip-api.com/json/$ip?fields=status,country,regionName,city,isp,org,as,asname,reverse,query" | json_pretty || true
    section "Reverse DNS"; dig +short -x "$ip" || true
  } | log
}

# --- HTTP/TLS Check ---
run_http() {
  local url="$1"
  {
    if [[ "$FORMAT" == "md" ]]; then echo "# HTTP/TLS check for: $url ($(timestamp))"; else echo "$HLINE"; ok "HTTP/TLS check for: $url (UTC: $(timestamp))"; echo "$HLINE"; fi

    section "Response Headers"
    local headers=$(curl -fsSLI "$url" || true)
    echo "$headers"

    section "Security Header Audit"
    for h in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy"; do
      if echo "$headers" | grep -iq "$h"; then ok "$h present"; else err "$h missing"; fi
    done

    local host=$(echo "$url" | sed -E 's~^[a-z]+://([^/:]+).*$~\1~')
    local port=$(echo "$url" | sed -nE 's~^[a-z]+://[^/:]+:([0-9]+).*~\1~p')
    [[ -z "${port:-}" ]] && port=443

    if [[ "$url" =~ ^https?:// ]]; then
      section "TLS Certificate Summary"
      echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | openssl x509 -noout -issuer -subject -dates -ext subjectAltName || true
    fi

    if command -v whatweb >/dev/null 2>&1; then section "Tech Fingerprint (whatweb)"; whatweb --colour=never --no-errors "$url" || true; else echo "(whatweb not installed)"; fi
  } | log
}

# --- File Metadata ---
run_file() {
  local path="$1"
  {
    if [[ "$FORMAT" == "md" ]]; then echo "# File metadata for: $path ($(timestamp))"; else echo "$HLINE"; ok "File metadata for: $path (UTC: $(timestamp))"; echo "$HLINE"; fi
    [[ -f "$path" ]] || { err "File not found: $path"; exit 1; }
    if command -v exiftool >/dev/null 2>&1; then exiftool "$path" || true; else err "exiftool not installed; fallback"; head -c 4096 "$path" | strings | sed -n '1,80p' || true; fi
  } | log
}

# --- Reporting Checklist ---
report_checklist() {
  {
    if [[ "$FORMAT" == "md" ]]; then echo "# Responsible Reporting Checklist"; else echo "$HLINE"; ok "Responsible Reporting Checklist"; echo "$HLINE"; fi
    cat <<EOF
- Verify findings against multiple sources.
- Avoid storing/sharing personal data or secrets.
- Document:
  * Target (domain/IP/URL)
  * Evidence (headers, TLS info, snapshots)
  * Potential impact (security headers missing, outdated certs)
  * Recommended fixes
- Share only with authorized contacts (security@domain or disclosure program).
- Respect laws and terms of service.
EOF
  } | log
}

# --- Interactive Menu ---
menu() {
  while true; do
    echo "$HLINE"
    echo "OSINT Toolkit — choose an option:"
    echo "  1) Domain intel"
    echo "  2) IP intel"
    echo "  3) HTTP/TLS check"
    echo "  4) File metadata"
    echo "  5) Reporting checklist"
    echo "  6) Quit"
    echo -n "> "; read -r ch
    case "$ch" in
      1) echo -n "Domain: "; read -r d; run_domain "$d" ;;
      2) echo -n "IP: "; read -r i; run_ip "$i" ;;
      3) echo -n "URL: "; read -r u; run_http "$u" ;;
      4) echo -n "File path: "; read -r f; run_file "$f" ;;
      5) report_checklist ;;
      6) echo "Report saved to $OUTFILE"; exit 0 ;;
      *) echo "Unknown choice" ;;
    esac
  done
}

# --- Dispatcher ---
case "${1:-menu}" in
  domain) shift; run_domain "$1"; echo "Report saved to $OUTFILE" ;;
  ip) shift; run_ip "$1"; echo "Report saved to $OUTFILE" ;;
  http) shift; run_http "$1"; echo "Report saved to $OUTFILE" ;;
  file) shift; run_file "$1"; echo "Report saved to $OUTFILE" ;;
  checklist) report_checklist; echo "Report saved to $OUTFILE" ;;
  menu|*) menu ;;
esac
