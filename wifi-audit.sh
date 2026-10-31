#!/usr/bin/env bash
# wifi-audit.sh — security audit of YOUR OWN Wi-Fi network (e.g. "MyHomeWiFi").
#
#   AUTHORISED USE ONLY. Run only against a network you own or have written
#   permission to test. Every active action is scoped to the single BSSID given.
#
# Safe by default: passive recon (encryption/WPS/PMF) + router service scan.
# Active tests (short targeted deauth -> handshake -> offline passphrase test,
# and WPS Pixie-Dust) run ONLY with --active.
#
# Usage:
#   sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi"              # passive audit
#   sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi" --router     # + scan the router
#   sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi" --active     # + passphrase/WPS tests
#   extra: -b <BSSID> (skip scan), -w <wordlist>, -t <sec capture>
set -uo pipefail

IFACE=""; SSID=""; BSSID=""; ACTIVE=0; ROUTER=0; CAPT=90
WORDLIST="/usr/share/wordlists/rockyou.txt"
REPORT="$HOME/wifi-audit-$(date +%F_%H%M).txt"
CH=""; ENC=""; CIP=""; AUTH=""; WPSROW=""
declare -a FIND

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
hd(){  printf "\n${B}${C}== %s ==${N}\n" "$*"; }
say(){ printf "  %s\n" "$*"; }
add(){ FIND+=("$1|$2"); printf "  ${R}[%s]${N} %s\n" "$1" "$2"; }

while [ $# -gt 0 ]; do case "$1" in
  -i) IFACE="$2"; shift 2;; -s) SSID="$2"; shift 2;; -b) BSSID="$2"; shift 2;;
  -w) WORDLIST="$2"; shift 2;; -t) CAPT="$2"; shift 2;;
  --active) ACTIVE=1; shift;; --router) ROUTER=1; shift;;
  *) echo "unknown arg: $1"; exit 2;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -n "$IFACE" ] && [ -n "$SSID" ] || { echo "need -i <iface> and -s <ssid>"; exit 2; }

hd "Scope"
say "Target: ${B}${SSID}${N} — this audits ONLY this network. Authorised/own-network use only."
say "Report -> ${REPORT}"

hd "Tooling"
need=""; for t in airmon-ng airodump-ng aireplay-ng aircrack-ng wash reaver nmap iw curl; do
  command -v "$t" >/dev/null || need="$need $t"; done
[ -n "$need" ] && say "${Y}missing:${need}${N} -> sudo apt install -y aircrack-ng reaver nmap hcxtools hcxdumptool" \
                || say "all core tools present"

# ---- router/service audit (managed mode; run while connected, before monitor) ----
if [ "$ROUTER" -eq 1 ]; then
  hd "Router / gateway service audit"
  GW=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
  if [ -z "${GW:-}" ]; then
    say "${Y}not connected — join ${SSID} first, then re-run with --router${N}"
  else
    say "gateway: $GW  (scanning common + router-specific ports)"
    OUT=$(nmap -Pn -T4 --open -sV -p 21,22,23,53,80,139,443,445,1900,7547,8080,8443,9000 "$GW" 2>/dev/null)
    printf '%s\n' "$OUT" | sed 's/^/    /'
    printf '%s' "$OUT" | grep -q '23/tcp'   && add HIGH "Telnet (23) open on router — classic default/backdoor creds"
    printf '%s' "$OUT" | grep -q '7547/tcp' && add HIGH "TR-069/CWMP (7547) exposed — remote-management attack surface"
    printf '%s' "$OUT" | grep -q '1900/tcp' && add MED  "UPnP (1900) open — can auto-open firewall holes"
    printf '%s' "$OUT" | grep -qE '(80|443|8080|8443)/tcp' && add INFO "Admin web UI at $GW — verify it is NOT on default credentials"
    curl -skI "http://$GW" --max-time 6 2>/dev/null | tr -d '\r' | grep -i '^server:' | sed 's/^/    banner: /'
  fi
fi

# ---- monitor mode ----
hd "Monitor mode"
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$IFACE" >/dev/null 2>&1
MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}' | head -1)
[ -z "${MON:-}" ] && MON="$IFACE"
say "monitor interface: $MON"
if aireplay-ng --test "$MON" 2>/dev/null | grep -qi 'Injection is working'; then
  say "${G}injection works${N}"
else
  say "${Y}injection test failed — expected on VM USB-passthrough / in-kernel rtw88."
  say "Passive recon still works; for deauth/WPS/handshake boot Kali natively from USB.${N}"
fi

# ---- passive recon: encryption, WPS ----
hd "Recon: encryption & WPS of '${SSID}'"
rm -f /tmp/wa-*.csv
timeout 25 airodump-ng --output-format csv -w /tmp/wa "$MON" >/dev/null 2>&1 || true
ROW=$(grep -F ",${SSID}" /tmp/wa-01.csv 2>/dev/null | head -1)
if [ -n "${ROW:-}" ]; then
  [ -z "$BSSID" ] && BSSID=$(printf '%s' "$ROW" | cut -d, -f1 | tr -d ' ')
  CH=$(printf '%s'   "$ROW" | cut -d, -f4 | tr -d ' ')
  ENC=$(printf '%s'  "$ROW" | cut -d, -f6 | tr -d ' ')
  CIP=$(printf '%s'  "$ROW" | cut -d, -f7 | tr -d ' ')
  AUTH=$(printf '%s' "$ROW" | cut -d, -f8 | tr -d ' ')
  say "BSSID $BSSID  ch $CH  enc=$ENC cipher=$CIP auth=$AUTH"
  case "$ENC" in
    *OPN*) add CRIT "Open network — no encryption at all";;
    *WEP*) add CRIT "WEP — crackable in minutes";;
    *WPA3*) say "${G}WPA3/SAE present — good${N}";;
    WPA2)   add LOW "WPA2 only (no WPA3/SAE) — OK only with a strong passphrase";;
    *WPA2*) say "WPA2 (mixed) — see passphrase test";;
    *WPA*)  add MED "WPA v1 — weak, upgrade to WPA2/3";;
  esac
  printf '%s' "$AUTH" | grep -qi 'MGT' && say "enterprise (802.1X) auth"
else
  say "${Y}'${SSID}' not seen in 25s — is it on, in range, and monitor mode up?${N}"
fi
WPSROW=$(timeout 20 wash -i "$MON" 2>/dev/null | grep -iF "$SSID" | head -1 || true)
if [ -n "${WPSROW:-}" ]; then
  printf '%s' "$WPSROW" | grep -qi ' yes ' && L="LOCKED" || L="unlocked"
  add HIGH "WPS ENABLED ($L) — if unlocked, exposed to Pixie-Dust / PIN brute-force"
else
  say "${G}WPS not advertised (good), or not captured${N}"
fi

# ---- active: handshake + offline passphrase strength, WPS Pixie-Dust ----
if [ "$ACTIVE" -eq 1 ] && [ -n "${BSSID:-}" ]; then
  hd "Active tests (scoped to $BSSID)"
  say "${Y}sends a few deauth frames to ${BSSID} ONLY to force a handshake — briefly drops that AP's"
  say "own clients. Ctrl-C to abort.${N}"
  rm -f /tmp/hs-*.cap
  ( timeout "$CAPT" airodump-ng -c "${CH:-1}" --bssid "$BSSID" -w /tmp/hs --output-format pcap "$MON" >/dev/null 2>&1 ) &
  cap=$!; sleep 8
  aireplay-ng --deauth 4 -a "$BSSID" "$MON" >/dev/null 2>&1 || true
  wait "$cap" 2>/dev/null || true
  CAP=$(ls -t /tmp/hs-*.cap 2>/dev/null | head -1)
  if [ -n "${CAP:-}" ] && aircrack-ng "$CAP" 2>/dev/null | grep -qi 'handshake'; then
    say "${G}handshake captured${N} — testing passphrase vs $(basename "$WORDLIST")"
    if [ -f "$WORDLIST" ]; then
      RES=$(aircrack-ng -w "$WORDLIST" -b "$BSSID" "$CAP" 2>/dev/null)
      if printf '%s' "$RES" | grep -qi 'KEY FOUND'; then
        KEY=$(printf '%s' "$RES" | grep -i 'KEY FOUND' | sed 's/.*\[ *//; s/ *\].*//')
        add CRIT "Passphrase cracked from wordlist: '${KEY}' — use a long random passphrase"
      else
        say "${G}passphrase NOT in $(basename "$WORDLIST") — resists a basic dictionary attack${N}"
      fi
    else
      say "${Y}wordlist missing: sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz${N}"
    fi
  else
    say "${Y}no handshake (no clients connected, or injection blocked in the VM)${N}"
  fi
  if [ -n "${WPSROW:-}" ]; then
    say "WPS Pixie-Dust on $BSSID (up to 60s)..."
    PIX=$(timeout 60 reaver -i "$MON" -b "$BSSID" -c "${CH:-1}" -K 1 -N 2>/dev/null || true)
    if printf '%s' "$PIX" | grep -qiE 'WPS PIN|WPA PSK|Pixie'; then
      add CRIT "WPS Pixie-Dust recovered the PIN/PSK offline — DISABLE WPS on the router"
      printf '%s\n' "$PIX" | grep -iE 'WPS PIN|WPA PSK' | sed 's/^/    /'
    else
      say "${G}Pixie-Dust did not succeed in 60s${N}"
    fi
  fi
fi

# ---- restore ----
hd "Restore networking"
airmon-ng stop "$MON" >/dev/null 2>&1 || true
systemctl restart NetworkManager >/dev/null 2>&1 || service network-manager restart >/dev/null 2>&1 || true
say "monitor mode off, NetworkManager restarted"

# ---- report ----
hd "Findings"
if [ "${#FIND[@]}" -eq 0 ]; then
  printf "  ${G}${B}No weaknesses flagged by the checks that ran.${N}\n"
else
  for f in "${FIND[@]}"; do IFS='|' read -r s t <<<"$f"; printf "  ${R}%-5s${N} %s\n" "$s" "$t"; done
fi
{ echo "Wi-Fi audit — $SSID — $(date)"
  echo "BSSID=${BSSID:-?} CH=${CH:-?} ENC=${ENC:-?} CIPHER=${CIP:-?} AUTH=${AUTH:-?}"
  echo "---"; printf '%s\n' "${FIND[@]:-(none)}"; } > "$REPORT"
say "report saved: $REPORT"
