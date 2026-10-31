#!/usr/bin/env bash
# net-audit.sh — comprehensive security audit of YOUR OWN network/router (e.g. MyHomeWiFi).
# AUTHORISED / OWN-NETWORK USE ONLY. Every action is scoped to the one target you pass.
#
# Default: recon + service/version scan + default-credentials check + report.
# Flags add teeth:
#   --exploit  nmap vuln scripts + searchsploit + RouterSploit autopwn (active)
#   --brute    hydra credential brute on http/ssh/telnet + SNMP community guess (noisy)
#   --upnp     UPnP/IGD + SNMP enumeration
#   --wifi     radio audit: enc/WPS recon, handshake+PMKID capture, WPA crack, WPS Pixie
#              (needs monitor+injection — run this module on the Raspberry Pi)
#   --all      all of the above
# Args: -t <ip|auto> (auto=gateway)  -s <ssid>  -i <iface>  -u users -P pass  -w psk_wordlist
set -uo pipefail

TGT="auto"; SSID=""; IFACE="wlan0"; DO_EXPL=0; DO_BRUTE=0; DO_UPNP=0; DO_WIFI=0
ULIST=""; PLIST=""; PSK_WL="/usr/share/wordlists/rockyou.txt"
REPORT="$HOME/net-audit-$(date +%F_%H%M).txt"
AUTH=""; declare -a FIND
B=$'\e[1m';G=$'\e[32m';Y=$'\e[33m';R=$'\e[31m';C=$'\e[36m';N=$'\e[0m'
hd(){ printf "\n${B}${C}== %s ==${N}\n" "$*"; echo "== $* ==" >>"$REPORT"; }
say(){ printf "  %s\n" "$*"; echo "  $*" >>"$REPORT"; }
add(){ FIND+=("$1|$2"); printf "  ${R}[%s]${N} %s\n" "$1" "$2"; }

while [ $# -gt 0 ]; do case "$1" in
  -t) TGT="$2";shift 2;; -s) SSID="$2";shift 2;; -i) IFACE="$2";shift 2;;
  -u) ULIST="$2";shift 2;; -P) PLIST="$2";shift 2;; -w) PSK_WL="$2";shift 2;;
  --exploit) DO_EXPL=1;shift;; --brute) DO_BRUTE=1;shift;; --upnp) DO_UPNP=1;shift;;
  --wifi) DO_WIFI=1;shift;; --all) DO_EXPL=1;DO_BRUTE=1;DO_UPNP=1;DO_WIFI=1;shift;;
  *) echo "unknown: $1"; exit 2;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
: > "$REPORT"

# high-signal router default creds (user:pass)
DEFCREDS=$'admin:admin\nadmin:password\nadmin:\nadmin:1234\nadmin:12345\nroot:root\nroot:admin\nroot:\nuser:user\nadmin:0000\nsupport:support\nadmin:admin123'

hd "Scope"
[ "$TGT" = "auto" ] && TGT=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
say "target: ${B}${TGT:-?}${N}   report -> $REPORT"
say "AUTHORISED OWN-NETWORK USE ONLY — actions are scoped to this target."
[ -n "${TGT:-}" ] || say "${Y}no target/gateway — connect to the network or pass -t <ip>${N}"

hd "Tooling"
miss=""; for t in nmap hydra searchsploit snmpwalk onesixtyone upnpc routersploit \
                  airmon-ng airodump-ng aireplay-ng aircrack-ng wash reaver bully hcxdumptool hcxpcapngtool; do
  command -v "$t" >/dev/null || miss="$miss $t"; done
[ -n "$miss" ] && say "${Y}missing:${miss}${N}
    sudo apt install -y nmap hydra exploitdb snmp onesixtyone miniupnpc routersploit \\
      aircrack-ng reaver bully hcxtools hcxdumptool" || say "all tools present"

# ===================== NETWORK / ROUTER (works in the VM once connected) =====================
if [ -n "${TGT:-}" ]; then
  hd "Recon — ports & service versions ($TGT)"
  XML=/tmp/na-nmap.xml
  nmap -Pn -T4 -sV -O --top-ports 1000 -oX "$XML" "$TGT" 2>/dev/null | sed 's/^/  /' | tee -a "$REPORT" >/dev/null
  nmap -Pn -T4 -sV --top-ports 1000 "$TGT" 2>/dev/null | grep -E '^[0-9]+/tcp' | sed 's/^/  /'
  grep -q 'portid="23"'   "$XML" 2>/dev/null && add HIGH "Telnet(23) open — default/backdoor creds likely"
  grep -q 'portid="7547"' "$XML" 2>/dev/null && add HIGH "TR-069/CWMP(7547) exposed — remote-management surface"
  grep -q 'portid="1900"' "$XML" 2>/dev/null && add MED  "UPnP(1900) open"
  grep -q 'portid="161"'  "$XML" 2>/dev/null && add MED  "SNMP(161) open — check community strings"

  hd "Default-credentials check ($TGT)"
  AUTH=$(curl -skI "http://$TGT" --max-time 6 2>/dev/null | tr -d '\r' | grep -i '^www-authenticate' || true)
  if printf '%s' "$AUTH" | grep -qi basic; then
    say "HTTP Basic auth — trying built-in default creds"
    while IFS=: read -r u p; do
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -u "$u:$p" "http://$TGT/" 2>/dev/null)
      [ "$code" = "200" ] && { add CRIT "Router admin accepts default creds: ${u}/${p:-<blank>}"; break; }
    done <<< "$DEFCREDS"
  else
    say "no HTTP Basic (likely a login form) — admin UI at http://$TGT ; use --brute with its form path"
  fi

  if [ "$DO_EXPL" -eq 1 ]; then
    hd "Exploit scan — nmap vuln + searchsploit + RouterSploit ($TGT)"
    nmap -Pn -T4 --script vuln "$TGT" 2>/dev/null | sed 's/^/  /' | tee -a "$REPORT"
    command -v searchsploit >/dev/null && { say "searchsploit vs detected versions:"; searchsploit --nmap "$XML" 2>/dev/null | sed 's/^/  /' | tee -a "$REPORT"; }
    if command -v routersploit >/dev/null; then
      say "RouterSploit autopwn (known router/IoT exploits)..."
      printf 'use scanners/autopwn\nset target %s\nrun\nexit\n' "$TGT" | routersploit 2>/dev/null | sed 's/^/  /' | tee -a "$REPORT"
      say "(if a module is flagged vulnerable, confirm it interactively: routersploit -> use <module>)"
    fi
  fi

  if [ "$DO_BRUTE" -eq 1 ]; then
    hd "Credential brute-force ($TGT) — noisy; own device only"
    U=${ULIST:-/tmp/na-users}; P=${PLIST:-/tmp/na-pass}
    [ -n "$ULIST" ] || printf 'admin\nroot\nuser\nsupport\n' > "$U"
    [ -n "$PLIST" ] || { printf '%s\n' "$DEFCREDS" | cut -d: -f2 | sort -u > "$P"; printf 'admin\npassword\n123456\n12345678\nadmin123\n' >> "$P"; }
    for pair in "ssh:22" "telnet:23"; do
      svc=${pair%%:*}; port=${pair##*:}
      grep -q "portid=\"$port\"" "$XML" 2>/dev/null || continue
      say "hydra $svc on $TGT ..."
      hydra -L "$U" -P "$P" -t 4 -f -o "/tmp/na-$svc.txt" "$svc://$TGT" 2>/dev/null | grep -i 'login:' | sed 's/^/  /'
      [ -s "/tmp/na-$svc.txt" ] && add CRIT "$svc credentials found (see /tmp/na-$svc.txt)"
    done
    if printf '%s' "$AUTH" | grep -qi basic; then
      say "hydra http-basic ..."; hydra -L "$U" -P "$P" -t 4 -f "$TGT" http-get / 2>/dev/null | grep -i 'login:' | sed 's/^/  /'
    else
      say "${Y}form login — inspect the POST then run, e.g.:"
      say "  hydra -L $U -P $P $TGT http-post-form \"/login:user=^USER^&pass=^PASS^:F=incorrect\"${N}"
    fi
  fi

  if [ "$DO_UPNP" -eq 1 ]; then
    hd "UPnP / SNMP ($TGT)"
    if command -v upnpc >/dev/null; then upnpc -l 2>/dev/null | sed 's/^/  /' | tee -a "$REPORT"
      upnpc -l 2>/dev/null | grep -qi 'desc:' && add MED "UPnP IGD responds — a LAN host can open firewall ports"; fi
    if command -v onesixtyone >/dev/null; then printf 'public\nprivate\ncisco\nadmin\n' > /tmp/na-comm
      onesixtyone -c /tmp/na-comm "$TGT" 2>/dev/null | sed 's/^/  /' | grep -qi '\[' && add HIGH "SNMP community guessable — snmpwalk can dump config/creds"; fi
  fi
fi

# ===================== WIFI RADIO (run on the Raspberry Pi) =====================
if [ "$DO_WIFI" -eq 1 ]; then
  if [ -z "$SSID" ]; then say "${Y}--wifi needs -s \"SSID\"${N}"; else
  hd "WiFi radio audit — $SSID (needs monitor+injection)"
  airmon-ng check kill >/dev/null 2>&1; airmon-ng start "$IFACE" >/dev/null 2>&1
  MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2}/type monitor/{print i}' | head -1); [ -z "${MON:-}" ] && MON="$IFACE"
  INJ=0; aireplay-ng --test "$MON" 2>/dev/null | grep -qi 'Injection is working' && INJ=1
  [ "$INJ" = 1 ] && say "${G}injection works${N}" || say "${Y}no injection (VM/driver) — capture-only; crack/WPS limited${N}"
  rm -f /tmp/na-wa-*.csv; timeout 25 airodump-ng --output-format csv -w /tmp/na-wa "$MON" >/dev/null 2>&1 || true
  ROW=$(grep -F ",${SSID}" /tmp/na-wa-01.csv 2>/dev/null | head -1); BSSID=""; CH=""; ENC=""
  if [ -n "${ROW:-}" ]; then
    BSSID=$(echo "$ROW"|cut -d, -f1|tr -d ' '); CH=$(echo "$ROW"|cut -d, -f4|tr -d ' '); ENC=$(echo "$ROW"|cut -d, -f6|tr -d ' ')
    say "BSSID $BSSID ch $CH enc=$ENC"
    case "$ENC" in *OPN*) add CRIT "Open WiFi — no encryption";; *WEP*) add CRIT "WEP — crackable in minutes";;
      *WPA3*) say "${G}WPA3 present${N}";; WPA2) add LOW "WPA2-only — needs a strong passphrase";; *WPA*) add MED "WPA1 — weak";; esac
  else say "${Y}$SSID not seen in scan${N}"; fi
  WPS=$(timeout 20 wash -i "$MON" 2>/dev/null | grep -iF "$SSID" | head -1 || true)
  [ -n "${WPS:-}" ] && add HIGH "WPS enabled — Pixie-Dust / PIN brute possible"
  if [ -n "$BSSID" ]; then
    rm -f /tmp/na-hs*; ( timeout 90 airodump-ng -c "${CH:-1}" --bssid "$BSSID" -w /tmp/na-hs --output-format pcap "$MON" >/dev/null 2>&1 ) & cp=$!
    sleep 8; [ "$INJ" = 1 ] && aireplay-ng --deauth 5 -a "$BSSID" "$MON" >/dev/null 2>&1 || true
    timeout 45 hcxdumptool -i "$MON" -o /tmp/na-pmkid.pcapng --enable_status=1 >/dev/null 2>&1 || true
    wait "$cp" 2>/dev/null || true
    HS=$(ls -t /tmp/na-hs*.cap 2>/dev/null | head -1)
    if [ -n "${HS:-}" ] && aircrack-ng "$HS" 2>/dev/null | grep -qi handshake; then
      say "handshake captured — testing vs $(basename "$PSK_WL")"
      [ -f "$PSK_WL" ] && aircrack-ng -w "$PSK_WL" -b "$BSSID" "$HS" 2>/dev/null | grep -qi 'KEY FOUND' && add CRIT "WPA passphrase is in the wordlist — weak"
    fi
    if [ -f /tmp/na-pmkid.pcapng ] && command -v hcxpcapngtool >/dev/null; then
      hcxpcapngtool -o /tmp/na-hash.hc22000 /tmp/na-pmkid.pcapng >/dev/null 2>&1
      [ -s /tmp/na-hash.hc22000 ] && say "PMKID captured -> crack: hashcat -m 22000 /tmp/na-hash.hc22000 $PSK_WL"
    fi
    if [ -n "${WPS:-}" ] && [ "$INJ" = 1 ]; then
      say "WPS Pixie-Dust..."; timeout 90 reaver -i "$MON" -b "$BSSID" -c "${CH:-1}" -K 1 -N 2>/dev/null | grep -qiE 'WPS PIN|WPA PSK' && add CRIT "WPS Pixie-Dust recovered PIN/PSK — disable WPS"
    fi
  fi
  airmon-ng stop "$MON" >/dev/null 2>&1 || true; systemctl restart NetworkManager >/dev/null 2>&1 || true
  fi
fi

# ---- report ----
hd "Findings summary"
if [ "${#FIND[@]}" -eq 0 ]; then printf "  ${G}${B}No weaknesses flagged by the modules that ran.${N}\n"
else for f in "${FIND[@]}"; do IFS='|' read -r s t <<<"$f"; printf "  ${R}%-5s${N} %s\n" "$s" "$t"; echo "  $s $t" >>"$REPORT"; done; fi
say "full report: $REPORT"
