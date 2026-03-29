#!/usr/bin/env bash
# OSINT Toolkit (Ethical Edition) — v2.0
# Fixes: retry/backoff, parallel API calls, strict validation,
#        input sanitization, clean optional-dep handling, robust error handling

# ── CATATAN: -e dihapus intentional ──────────────────────────────────────────
# set -e akan membunuh script saat ada subcommand gagal (e.g. curl timeout).
# Kita handle error per-fungsi supaya satu kegagalan tidak stop segalanya.
set -uo pipefail

# ─── Warna output ─────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'
CYN=$'\033[0;36m'; BLD=$'\033[1m'; RST=$'\033[0m'

err()  { echo "${RED}[!]${RST} $*" >&2; }
warn() { echo "${YEL}[~]${RST} $*" >&2; }
info() { echo "${CYN}[i]${RST} $*"; }
ok()   { echo "${GRN}[+]${RST} $*"; }

# ─── Dependency checks ────────────────────────────────────────────────────────
need_hard() {
  command -v "$1" >/dev/null 2>&1 \
    || { err "Dependency wajib tidak ditemukan: ${BLD}$1${RST} — install dulu."; exit 1; }
}
has() { command -v "$1" >/dev/null 2>&1; }

need_hard curl
need_hard jq
need_hard dig
need_hard whois
need_hard openssl

# Dependency opsional — di-probe sekali di awal, tidak ada warning berulang
HAS_WHATWEB=false;  has whatweb   && HAS_WHATWEB=true
HAS_EXIFTOOL=false; has exiftool  && HAS_EXIFTOOL=true

# ─── Konfigurasi global ───────────────────────────────────────────────────────
HLINE=$(printf '%*s\n' 80 '' | tr ' ' '-')
CURL_TIMEOUT=15      # detik per request
RETRY_MAX=3          # maks percobaan ulang per API call
RETRY_BASE_DELAY=2   # detik, akan di-double tiap retry (exponential backoff)
PARALLEL_JOBS=5      # maks background jobs berjalan bersamaan

# Tempdir global — dibersihkan otomatis saat script exit/error
_TMPDIR=$(mktemp -d)
trap 'rm -rf "$_TMPDIR"' EXIT INT TERM

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# ─── Output / logging ─────────────────────────────────────────────────────────
FORMAT="txt"
[[ "${1:-}" == "--md" ]] && { FORMAT="md"; shift; }
OUTFILE="osint_report_$(date +%Y%m%d_%H%M%S).$FORMAT"

log() { tee -a "$OUTFILE"; }   # pipe ke layar DAN file

section() {
  [[ "$FORMAT" == "md" ]] \
    && echo -e "\n## $1\n" \
    || echo -e "\n${BLD}=== $1 ===${RST}"
}

header() {
  [[ "$FORMAT" == "md" ]] \
    && echo -e "# $1 ($(timestamp))" \
    || { echo "$HLINE"; ok "$1 (UTC: $(timestamp))"; echo "$HLINE"; }
}

# ─── Sanitasi input ───────────────────────────────────────────────────────────
# Hapus semua karakter di luar daftar putih ketat
sanitize_domain() {
  # Hanya huruf, angka, titik, strip
  local v="${1//[^a-zA-Z0-9.\-]}"
  echo "${v,,}"   # lowercase
}

sanitize_ip() {
  # Hanya hex, titik, titik dua (IPv4 + IPv6)
  echo "${1//[^a-fA-F0-9.:]}"
}

sanitize_url() {
  # Karakter legal di URL; strip newline/whitespace
  local v; v=$(echo "$1" | tr -d $'\n\r\t ')
  echo "${v//[^a-zA-Z0-9._~:/?#\[\]@!\$\&\'()*+,;=%\-]}"
}

sanitize_path() {
  # Hanya izinkan path normal, tolak traversal
  local v="$1"
  [[ "$v" =~ \.\. ]] && { err "Path traversal terdeteksi, ditolak."; return 1; }
  echo "$v"
}

# ─── Validasi ─────────────────────────────────────────────────────────────────
valid_domain() {
  local d="$1"
  # Panjang total max 253 karakter
  [[ ${#d} -ge 3 && ${#d} -le 253 ]] || return 1
  # Setiap label 1-63 karakter, tidak boleh mulai/akhir dengan strip
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || return 1
  # Tolak pure IPv4 yang lolos regex di atas
  [[ "$d" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1
  return 0
}

valid_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.' octets=($1)
  for oct in "${octets[@]}"; do
    # Tolak leading zero (010 bukan valid desimal)
    [[ "$oct" =~ ^0[0-9]+$ ]] && return 1
    [[ "$oct" -le 255 ]] 2>/dev/null || return 1
  done
}

valid_ipv6() {
  # Minimal ada satu titik dua dan hanya karakter hex + titik dua
  [[ "$1" == *:* && "$1" =~ ^[A-Fa-f0-9:]+$ ]]
}

valid_ip() { valid_ipv4 "$1" || valid_ipv6 "$1"; }

valid_url() {
  local u="$1"
  [[ "$u" =~ ^https?:// ]] || return 1
  local host; host=$(echo "$u" | sed -E 's~^https?://([^/:?#]*).*~\1~')
  [[ -n "$host" ]] || return 1
  # Host harus berupa domain atau IP valid
  valid_domain "$host" || valid_ip "$host" || return 1
}

# ─── Retry curl dengan exponential backoff ────────────────────────────────────
# Usage: retry_curl [--jq 'filter'] <url> [curl_extra_args...]
# Output ke stdout; return 1 jika semua retry gagal
retry_curl() {
  local jq_filter=""
  if [[ "${1:-}" == "--jq" ]]; then
    jq_filter="$2"; shift 2
  fi

  local url="$1"; shift
  local attempt=1 delay=$RETRY_BASE_DELAY
  local raw_output http_code body

  while [[ $attempt -le $RETRY_MAX ]]; do
    # -w "\n__CODE__%{http_code}" supaya kita tahu status tanpa -f (yang hide output)
    raw_output=$(curl -sS \
      --max-time "$CURL_TIMEOUT" \
      --location \
      -A "Mozilla/5.0 (compatible; OSINT-Toolkit/2.0; +https://github.com/osint)" \
      -H "Accept: application/json, text/plain, */*" \
      -w $'\n__CODE__%{http_code}' \
      "$@" "$url" 2>/dev/null) || true

    http_code="${raw_output##*$'\n'__CODE__}"
    body="${raw_output%$'\n'__CODE__*}"

    case "$http_code" in
      429)
        warn "Rate-limited oleh $(echo "$url" | awk -F/ '{print $3}') — tunggu ${delay}s (percobaan $attempt/$RETRY_MAX)"
        sleep "$delay"
        ;;
      2[0-9][0-9])
        if [[ -n "$body" ]]; then
          if [[ -n "$jq_filter" ]]; then
            echo "$body" | jq -r "$jq_filter" 2>/dev/null \
              || { warn "jq parse gagal — output mentah"; echo "$body"; }
          else
            echo "$body"
          fi
          return 0
        fi
        warn "Response kosong dari $(echo "$url" | awk -F/ '{print $3}') (percobaan $attempt/$RETRY_MAX)"
        ;;
      "")
        warn "curl timeout/network error (percobaan $attempt/$RETRY_MAX)"
        ;;
      *)
        warn "HTTP $http_code dari $(echo "$url" | awk -F/ '{print $3}') (percobaan $attempt/$RETRY_MAX)"
        ;;
    esac

    sleep "$delay"
    delay=$(( delay * 2 ))
    (( attempt++ )) || true
  done

  return 1   # semua retry habis
}

# ─── Manajemen job paralel ────────────────────────────────────────────────────
declare -a _pids=()

_throttle() {
  # Tunggu jika sudah ada PARALLEL_JOBS job berjalan
  while true; do
    local live=()
    for pid in "${_pids[@]:-}"; do
      kill -0 "$pid" 2>/dev/null && live+=("$pid")
    done
    _pids=("${live[@]:-}")
    [[ ${#_pids[@]} -lt $PARALLEL_JOBS ]] && break
    sleep 0.2
  done
}

_wait_all() {
  local failed=0
  for pid in "${_pids[@]:-}"; do
    wait "$pid" 2>/dev/null || (( failed++ )) || true
  done
  _pids=()
  return 0   # selalu return 0; kegagalan sudah ditangkap per-job
}

# ─── Domain Intel ─────────────────────────────────────────────────────────────
run_domain() {
  local raw="$1"
  local domain; domain=$(sanitize_domain "$raw")

  if ! valid_domain "$domain"; then
    err "Domain tidak valid: '${raw}'"
    return 1
  fi

  local td; td=$(mktemp -d "$_TMPDIR/domain_XXXXXX")

  {
    header "Domain OSINT: $domain"

    # ── Mulai API calls paralel ───────────────────────────────────────────────

    # crt.sh — Certificate Transparency
    (
      local out
      if out=$(retry_curl --jq '.[].name_value' \
          "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null); then
        echo "$out" | sort -u | grep -v '^\*\.' | head -n 100 > "$td/crt_clean"
        echo "$out" | sort -u | grep '^\*\.'   | head -n 50  > "$td/crt_wildcard"
      else
        echo "(crt.sh tidak merespons setelah $RETRY_MAX percobaan)" > "$td/crt_clean"
      fi
    ) & _pids+=($!); _throttle

    # Wayback Machine CDX API
    (
      # collapse=urlkey → 1 snapshot per URL unik (lebih informatif dari limit mentah)
      if ! retry_curl --jq '.[] | @tsv' \
          "https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=timestamp,original&limit=10&collapse=urlkey&matchType=domain" \
          > "$td/wayback" 2>/dev/null; then
        echo "(Wayback Machine tidak merespons setelah $RETRY_MAX percobaan)" > "$td/wayback"
      fi
      # Hapus baris header kalau ada
      sed -i '/^timestamp/d' "$td/wayback" 2>/dev/null || true
    ) & _pids+=($!); _throttle

    # RDAP
    (
      if ! retry_curl "https://rdap.org/domain/$domain" \
          | jq -r '
              "Registered  : \(.events[]? | select(.eventAction=="registration") | .eventDate // "n/a")",
              "Expiry      : \(.events[]? | select(.eventAction=="expiration") | .eventDate // "n/a")",
              "Status      : \(.status // [] | join(", "))",
              "Registrar   : \(.entities[]? | select(.roles[]? == "registrar") | .vcardArray[1][]? | select(.[0]=="fn") | .[3] // "" | .[0:80])"
            ' 2>/dev/null > "$td/rdap"; then
        echo "(RDAP tidak tersedia)" > "$td/rdap"
      fi
    ) & _pids+=($!); _throttle

    # ── Sementara job berjalan, kerjakan query lokal ──────────────────────────

    section "DNS Records (A / AAAA / MX / NS / TXT)"
    for rr in A AAAA MX NS TXT; do
      local rr_out
      rr_out=$(dig +short "$domain" "$rr" 2>/dev/null) || true
      if [[ -n "$rr_out" ]]; then
        echo "-- $rr"; echo "$rr_out"; echo
      else
        echo "-- $rr: (tidak ada record)"
      fi
    done

    section "WHOIS"
    timeout 20 whois "$domain" 2>/dev/null | sed -n '1,200p' \
      || echo "(whois gagal atau timeout)"

    section "Reverse DNS untuk A Records"
    local a_ips
    a_ips=$(dig +short "$domain" A 2>/dev/null \
            | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)
    if [[ -z "$a_ips" ]]; then
      echo "(tidak ada A record)"
    else
      while IFS= read -r ip; do
        local ptr
        ptr=$(dig +short -x "$ip" 2>/dev/null) || true
        printf "%-18s → %s\n" "$ip" "${ptr:-(no PTR)}"
      done <<< "$a_ips"
    fi

    # ── Tunggu semua job selesai ──────────────────────────────────────────────
    _wait_all

    section "Certificate Transparency — Subdomains (crt.sh)"
    if [[ -s "$td/crt_clean" ]]; then
      local cnt; cnt=$(wc -l < "$td/crt_clean")
      echo "Ditemukan $cnt subdomain:"
      cat "$td/crt_clean"
      if [[ -s "$td/crt_wildcard" ]]; then
        echo; echo "Wildcard entries:"
        cat "$td/crt_wildcard"
      fi
    else
      cat "$td/crt_clean"
    fi

    section "Wayback Machine Snapshots (10 URL unik terbaru)"
    if [[ -s "$td/wayback" ]]; then
      printf "%-18s  %s\n" "Timestamp" "URL"
      printf "%-18s  %s\n" "---------" "---"
      while IFS=$'\t' read -r ts orig; do
        printf "%-18s  %s\n" "${ts:-?}" "${orig:-?}"
      done < "$td/wayback"
    else
      cat "$td/wayback" 2>/dev/null || echo "(tidak ada snapshot)"
    fi

    section "RDAP"
    cat "$td/rdap"

    section "HTTP Quick Check"
    _run_http_inner "https://$domain"

  } | log
}

# ─── IP Intel ─────────────────────────────────────────────────────────────────
run_ip() {
  local raw="$1"
  local ip; ip=$(sanitize_ip "$raw")

  if ! valid_ip "$ip"; then
    err "IP address tidak valid: '${raw}'"
    return 1
  fi

  local td; td=$(mktemp -d "$_TMPDIR/ip_XXXXXX")

  {
    header "IP OSINT: $ip"

    # ── Paralel API calls ─────────────────────────────────────────────────────

    # ip-api.com (gratis, 45 req/menit)
    (
      if ! retry_curl \
          "http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,reverse,query,mobile,proxy,hosting" \
          | jq -r '
              if .status == "success" then
                "Country   : \(.country) (\(.countryCode))",
                "Region    : \(.regionName)",
                "City      : \(.city)  ZIP: \(.zip)",
                "Coords    : \(.lat), \(.lon)",
                "ISP       : \(.isp)",
                "Org       : \(.org)",
                "AS        : \(.as)",
                "AS Name   : \(.asname)",
                "rDNS      : \(.reverse)",
                "Mobile    : \(.mobile)",
                "Proxy/VPN : \(.proxy)",
                "Hosting   : \(.hosting)"
              else
                "ip-api gagal: \(.message // "unknown error")"
              end
            ' 2>/dev/null > "$td/geo"; then
        echo "(ip-api.com tidak merespons setelah $RETRY_MAX percobaan — coba lagi nanti)" > "$td/geo"
      fi
    ) & _pids+=($!); _throttle

    # Shodan InternetDB (tidak perlu API key)
    (
      if ! retry_curl "https://internetdb.shodan.io/$ip" \
          | jq -r '
              "Open Ports : \(.ports // [] | map(tostring) | join(", "))",
              "Hostnames  : \(.hostnames // [] | join(", "))",
              "Tags       : \(.tags // [] | join(", "))",
              "Vulns (CVE): \(.vulns // [] | join(", "))"
            ' 2>/dev/null > "$td/shodan"; then
        echo "(Shodan InternetDB tidak merespons)" > "$td/shodan"
      fi
    ) & _pids+=($!); _throttle

    # ── Query lokal ───────────────────────────────────────────────────────────
    section "WHOIS"
    timeout 20 whois "$ip" 2>/dev/null | sed -n '1,200p' \
      || echo "(whois gagal atau timeout)"

    section "Reverse DNS"
    dig +short -x "$ip" 2>/dev/null || echo "(tidak ada PTR record)"

    _wait_all

    section "Geo / ASN (ip-api.com)"
    cat "$td/geo"

    section "Shodan InternetDB"
    cat "$td/shodan"

  } | log
}

# ─── HTTP/TLS Check ───────────────────────────────────────────────────────────
_run_http_inner() {
  local url="$1"

  local host; host=$(echo "$url" | sed -E 's~^https?://([^/:?#]*).*~\1~')
  local port; port=$(echo "$url" | sed -nE 's~^https?://[^/:]+:([0-9]+).*~\1~p')
  if [[ -z "${port:-}" ]]; then
    [[ "$url" =~ ^https:// ]] && port=443 || port=80
  fi

  section "Response Headers"
  local headers
  headers=$(curl -fsSLI \
    --max-time "$CURL_TIMEOUT" \
    -A "Mozilla/5.0 (compatible; OSINT-Toolkit/2.0)" \
    "$url" 2>/dev/null) || true
  echo "${headers:-(tidak ada response — host mungkin down atau memblok)}"

  section "Security Header Audit"
  local missing=0 total=6
  local sec_headers=(
    "Strict-Transport-Security"
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Referrer-Policy"
    "Permissions-Policy"
  )
  for h in "${sec_headers[@]}"; do
    if echo "$headers" | grep -iqE "^${h}:"; then
      ok "$h — ada"
    else
      err "$h — TIDAK ADA"
      (( missing++ )) || true
    fi
  done
  echo "Skor: $(( total - missing ))/$total security headers terpasang"

  if [[ "$url" =~ ^https:// ]]; then
    section "TLS Certificate"
    local tls
    tls=$(echo \
      | timeout 10 openssl s_client \
          -servername "$host" \
          -connect "$host:$port" \
          2>/dev/null \
      | openssl x509 -noout \
          -issuer -subject -dates -fingerprint -ext subjectAltName \
          2>/dev/null) \
      || tls="(TLS handshake gagal — port $port mungkin bukan HTTPS)"
    echo "$tls"
  fi

  section "Tech Fingerprint"
  if $HAS_WHATWEB; then
    whatweb --colour=never --no-errors --quiet "$url" 2>/dev/null \
      || echo "(whatweb error)"
  else
    info "whatweb tidak terinstall — dilewati (install: sudo apt install whatweb)"
  fi
}

run_http() {
  local raw="$1"
  local url; url=$(sanitize_url "$raw")

  # Auto-prefix kalau user lupa https://
  [[ "$url" =~ ^https?:// ]] || url="https://$url"

  if ! valid_url "$url"; then
    err "URL tidak valid: '${raw}'"
    return 1
  fi

  {
    header "HTTP/TLS Check: $url"
    _run_http_inner "$url"
  } | log
}

# ─── File Metadata ────────────────────────────────────────────────────────────
run_file() {
  local raw="$1"
  local path
  path=$(sanitize_path "$raw") || return 1

  {
    header "File Metadata: $path"

    if [[ ! -e "$path" ]]; then
      err "File tidak ditemukan: $path"; return 1
    fi
    if [[ ! -f "$path" ]]; then
      err "Bukan regular file: $path"; return 1
    fi
    if [[ ! -r "$path" ]]; then
      err "File tidak bisa dibaca (permission denied): $path"; return 1
    fi

    section "Info Dasar"
    file "$path" 2>/dev/null || true
    ls -lh "$path" 2>/dev/null || true
    local size; size=$(wc -c < "$path" 2>/dev/null) || size="?"
    echo "Ukuran: $size bytes"

    section "EXIF / Metadata"
    if $HAS_EXIFTOOL; then
      exiftool "$path" 2>/dev/null || echo "(exiftool error)"
    else
      info "exiftool tidak terinstall — dilewati (install: sudo apt install libimage-exiftool-perl)"
      section "Fallback: Strings (80 baris pertama)"
      strings "$path" 2>/dev/null | head -n 80 \
        || echo "(strings gagal)"
    fi

  } | log
}

# ─── Reporting Checklist ──────────────────────────────────────────────────────
report_checklist() {
  {
    header "Responsible Reporting Checklist"
    cat <<'EOF'
- Verifikasi temuan dari minimal dua sumber independen.
- JANGAN simpan, bagikan, atau ekspos PII / kredensial yang ditemukan.
- Dokumentasikan:
    * Target (domain / IP / URL)
    * Bukti (headers, TLS info, snapshots, CT logs)
    * Potensi dampak (header hilang, sertifikat kadaluarsa, subdomain terbuka)
    * Langkah remediasi yang direkomendasikan
- Laporkan hanya ke kontak resmi (security@domain atau program HackerOne/Bugcrowd).
- Patuhi hukum yang berlaku (UU ITE, GDPR, CFAA) dan ToS layanan.
- Hapus data sensitif setelah tidak diperlukan.
EOF
  } | log
}

# ─── Interactive Menu ─────────────────────────────────────────────────────────
menu() {
  echo; info "Output akan disimpan ke: ${BLD}$OUTFILE${RST}"
  while true; do
    echo "$HLINE"
    echo "${BLD}OSINT Toolkit v2.0${RST} — pilih opsi:"
    echo "  1) Domain intel"
    echo "  2) IP intel"
    echo "  3) HTTP/TLS check"
    echo "  4) File metadata"
    echo "  5) Reporting checklist"
    echo "  6) Keluar"
    echo -n "> "; read -r ch || break
    case "$ch" in
      1) echo -n "Domain: ";    read -r d || continue; [[ -n "${d:-}" ]] && run_domain "$d" ;;
      2) echo -n "IP: ";        read -r i || continue; [[ -n "${i:-}" ]] && run_ip    "$i" ;;
      3) echo -n "URL: ";       read -r u || continue; [[ -n "${u:-}" ]] && run_http  "$u" ;;
      4) echo -n "File path: "; read -r f || continue; [[ -n "${f:-}" ]] && run_file  "$f" ;;
      5) report_checklist ;;
      6) echo "Report disimpan → $OUTFILE"; exit 0 ;;
      *) warn "Pilihan tidak dikenal: '${ch}'" ;;
    esac
  done
}

# ─── Dispatcher ───────────────────────────────────────────────────────────────
case "${1:-menu}" in
  domain)
    shift
    [[ -n "${1:-}" ]] || { err "Usage: $0 domain <domain>"; exit 1; }
    run_domain "$1"
    echo "Report → $OUTFILE"
    ;;
  ip)
    shift
    [[ -n "${1:-}" ]] || { err "Usage: $0 ip <ip>"; exit 1; }
    run_ip "$1"
    echo "Report → $OUTFILE"
    ;;
  http)
    shift
    [[ -n "${1:-}" ]] || { err "Usage: $0 http <url>"; exit 1; }
    run_http "$1"
    echo "Report → $OUTFILE"
    ;;
  file)
    shift
    [[ -n "${1:-}" ]] || { err "Usage: $0 file <path>"; exit 1; }
    run_file "$1"
    echo "Report → $OUTFILE"
    ;;
  checklist)
    report_checklist
    echo "Report → $OUTFILE"
    ;;
  menu|*)
    menu
    ;;
esac
