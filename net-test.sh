#!/usr/bin/env bash
# net-test.sh — quick health check for a connection (e.g. "MyHomeWiFi").
# Read-only: it only measures, changes nothing. Ctrl-C to stop early.
# Usage:  ./net-test.sh [ping_target]      (default target: 1.1.1.1)
#   DL_URL=... UL_URL=...  to override the speed-test endpoints.
set -uo pipefail

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
else B=; G=; Y=; R=; C=; N=; fi
ok(){   printf "  ${G}OK${N}  %s\n" "$*"; }
warn(){ printf "  ${Y}! ${N}  %s\n" "$*"; }
bad(){  printf "  ${R}X ${N}  %s\n" "$*"; }
hd(){   printf "\n${B}${C}== %s ==${N}\n" "$*"; }

TARGET="${1:-1.1.1.1}"
DL_URL="${DL_URL:-https://speed.cloudflare.com/__down?bytes=25000000}"   # ~25 MB
UL_URL="${UL_URL:-https://speed.cloudflare.com/__up}"
VERDICT=0   # bumped on each warning/failure

# loss avg jitter  <- from one ping run (iputils format)
ping_stats(){
  local out loss rtt
  out=$(ping -n -c "${2:-20}" -i 0.2 -w "${3:-12}" "$1" 2>/dev/null) || true
  loss=$(printf '%s\n' "$out" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' | grep -oE '^[0-9]+(\.[0-9]+)?')
  rtt=$(printf  '%s\n' "$out" | awk -F'= ' '/rtt|round-trip/{print $2}')   # min/avg/max/mdev ms
  printf '%s|%s' "${loss:-}" "${rtt:-}"
}

printf "${B}Network test — %s — %s${N}\n" "$TARGET" "$(date '+%F %T')"

hd "Interface & route"
DEF=$(ip route show default 2>/dev/null | head -1)
IFACE=$(printf '%s\n' "$DEF" | grep -oE 'dev [^ ]+' | awk '{print $2}')
GW=$(printf   '%s\n' "$DEF" | awk '{print $3}')
if [ -n "${IFACE:-}" ]; then
  IPADDR=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
  ok "default via ${GW:-?} dev ${IFACE} (local ip ${IPADDR:-none})"
else
  bad "no default route — this box is not connected"; VERDICT=$((VERDICT+1))
fi

hd "Public IP / carrier"
PUB=$(curl -fsS --max-time 8 https://ipinfo.io/json 2>/dev/null)
if [ -n "$PUB" ]; then
  printf '%s\n' "$PUB" | grep -oE '"(ip|city|region|country|org)": *"[^"]*"' | sed 's/^/  /'
else
  warn "couldn't fetch public IP (no internet yet, or endpoint blocked)"; VERDICT=$((VERDICT+1))
fi

hd "Latency, loss & jitter"
if [ -n "${GW:-}" ]; then
  IFS='|' read -r gl grtt <<<"$(ping_stats "$GW" 10 6)"
  ok "gateway ${GW}: loss ${gl:-?}%, rtt ${grtt:-n/a}"
fi
IFS='|' read -r loss rtt <<<"$(ping_stats "$TARGET" 25 12)"
echo "  ${TARGET}: loss ${loss:-?}% ; min/avg/max/mdev ${rtt:-n/a}"
AVG=$(printf '%s' "$rtt" | cut -d/ -f2 | cut -d. -f1)
JIT=$(printf '%s' "$rtt" | cut -d/ -f4 | awk '{print $1}' | cut -d. -f1)
[ -n "${loss:-}" ] && { awk "BEGIN{exit !(${loss:-0}>2)}"  && { warn "packet loss ${loss}% is high for 4G"; VERDICT=$((VERDICT+1)); } || ok "loss ${loss}% ok"; }
[ -n "${AVG:-}"  ] && { awk "BEGIN{exit !(${AVG:-0}>120)}" && { warn "avg latency ${AVG} ms is high"; VERDICT=$((VERDICT+1)); }   || ok "avg latency ${AVG} ms ok"; }
[ -n "${JIT:-}"  ] && { awk "BEGIN{exit !(${JIT:-0}>30)}"  && { warn "jitter ${JIT} ms high (unstable link)"; VERDICT=$((VERDICT+1)); } || ok "jitter ${JIT} ms ok"; }

hd "DNS resolution"
for h in cloudflare.com google.com kali.org; do
  t0=$(date +%s.%N)
  if getent hosts "$h" >/dev/null 2>&1; then
    t1=$(date +%s.%N); ms=$(awk "BEGIN{printf \"%.0f\",($t1-$t0)*1000}")
    ok "$h resolved in ${ms} ms"
  else
    bad "$h did NOT resolve"; VERDICT=$((VERDICT+1))
  fi
done

hd "Download speed"
if command -v speedtest >/dev/null 2>&1; then
  speedtest --accept-license --accept-gdpr 2>/dev/null || speedtest || true
elif command -v speedtest-cli >/dev/null 2>&1; then
  speedtest-cli --simple || true
elif command -v curl >/dev/null 2>&1; then
  read -r size dur < <(curl -o /dev/null -s -w '%{size_download} %{time_total}\n' --max-time 45 "$DL_URL")
  if [ "${size:-0}" -gt 100000 ] 2>/dev/null; then
    mbps=$(awk "BEGIN{printf \"%.1f\", ($size*8)/($dur*1000000)}")
    mb=$(awk   "BEGIN{printf \"%.1f\", $size/1048576}")
    ok "downloaded ${mb} MB in ${dur}s = ${B}${mbps} Mbps${N}"
    awk "BEGIN{exit !($mbps<5)}" && { warn "under 5 Mbps — slow for 4G"; VERDICT=$((VERDICT+1)); } || ok "throughput ok"
  else
    bad "download test failed (no internet / URL blocked)"; VERDICT=$((VERDICT+1))
  fi
  warn "tip: 'sudo apt install speedtest-cli' for a server-matched test"
else
  bad "no curl/speedtest available"
fi

hd "Upload speed (quick)"
if command -v curl >/dev/null 2>&1; then
  dd if=/dev/zero of=/tmp/.ultest bs=1M count=8 status=none 2>/dev/null || true
  read -r usize udur < <(curl -o /dev/null -s -w '%{size_upload} %{time_total}\n' --max-time 45 -T /tmp/.ultest "$UL_URL" 2>/dev/null)
  rm -f /tmp/.ultest
  if [ "${usize:-0}" -gt 100000 ] 2>/dev/null; then
    umbps=$(awk "BEGIN{printf \"%.1f\", ($usize*8)/($udur*1000000)}")
    ok "uploaded $(awk "BEGIN{printf \"%.1f\",$usize/1048576}") MB in ${udur}s = ${B}${umbps} Mbps${N}"
  else
    warn "upload test skipped/failed"
  fi
fi

hd "Stability (30 s rolling ping)"
echo "  watching ${TARGET} for 30s — Ctrl-C to stop early..."
ping -n -w 30 "$TARGET" 2>/dev/null | awk -F'time=' '
  /time=/{split($2,a," "); n++; s+=a[1]; if(a[1]>mx)mx=a[1];
          printf "\r  replies=%d  last=%.0fms  avg=%.1fms  max=%.0fms      ", n, a[1], s/n, mx}
  END{printf "\n"; if(n==0) print "  (no replies — link down?)"}'

hd "Summary"
if [ "$VERDICT" -eq 0 ]; then printf "  ${G}${B}Healthy${N} — no problems flagged.\n"
elif [ "$VERDICT" -le 2 ]; then printf "  ${Y}${B}Usable, with %d warning(s)${N} — see the ! lines above.\n" "$VERDICT"
else printf "  ${R}${B}Problems: %d issue(s)${N} — see the X/! lines above.\n" "$VERDICT"; fi
echo "  Re-run after the WiFi adapter connects directly to MyHomeWiFi to measure the real link."
