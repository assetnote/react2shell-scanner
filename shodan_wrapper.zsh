#!/usr/bin/env zsh

# Wrapper script to fetch subdomains from Shodan and run scanner.py against them.
# Requires: shodan CLI authenticated, python3, scanner.py in the same directory.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
SCANNER="${SCRIPT_DIR}/scanner.py"

usage() {
echo "Usage: $0 <domain> [-- scanner_args...]"
  echo "  <domain>            Domain to query via 'shodan domain <domain>'"
  echo "  -- scanner_args...  Optional arguments passed directly to scanner.py"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

DOMAIN="$1"
shift || true  # Remaining args go to scanner.py
# Allow optional separator to avoid arg collisions.
if [[ "${1:-}" == "--" ]]; then
  shift
fi

if ! command -v shodan >/dev/null 2>&1; then
  echo "[ERROR] shodan CLI not found in PATH. Install and configure it first."
  exit 1
fi

if [[ ! -f "${SCANNER}" ]]; then
  echo "[ERROR] scanner.py not found at ${SCANNER}"
  exit 1
fi

# Temporary files for raw Shodan output and parsed hosts list.
RAW_OUT="$(mktemp -t shodan_domain_raw.XXXXXX)"
HOSTS_FILE="$(mktemp -t shodan_hosts.XXXXXX)"
cleanup() {
  rm -f "${RAW_OUT}" "${HOSTS_FILE}"
}
trap cleanup EXIT INT TERM

echo "[*] Querying Shodan for domain: ${DOMAIN}"
if ! shodan domain "${DOMAIN}" > "${RAW_OUT}"; then
  echo "[ERROR] Shodan query failed; check API key or network connectivity."
  exit 1
fi

# Extract first column (subdomain label) while ignoring record-type rows.
# If the token lacks a dot, append the domain to form FQDN.
awk -v domain="${DOMAIN}" '
  function is_type(token) {
    return (token ~ /^(A|AAAA|MX|NS|SOA|TXT|CNAME|SRV|PTR|CAA)$/)
  }
  {
    if (NF < 1) next
    token = $1
    if (token == "") next
    if (is_type(token)) next
    # Skip header-only lines that equal the uppercased domain.
    dom_up = toupper(domain)
    if (NF == 1 && toupper(token) == dom_up) next
    host = token
    if (index(host, ".") == 0) {
      host = host "." domain
    }
    print host
  }
' "${RAW_OUT}" | sort -u > "${HOSTS_FILE}"

if [[ ! -s "${HOSTS_FILE}" ]]; then
  echo "[ERROR] No hosts found in Shodan output for domain ${DOMAIN}"
  echo "[INFO] Raw output saved at ${RAW_OUT} for inspection."
  exit 1
fi

echo "[*] Found $(wc -l < "${HOSTS_FILE}") host(s). Launching scanner..."
echo "[*] Hosts list saved at ${HOSTS_FILE}"

python3 "${SCANNER}" -l "${HOSTS_FILE}" "$@"

