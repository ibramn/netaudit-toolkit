# netaudit-toolkit

Self-contained Bash scripts for auditing the security (and health) of your **own**
Wi-Fi networks and routers from Kali Linux or any Debian-based distro.

> ⚠️ **Authorized use only.** These tools are for testing networks and devices you
> **own** or have **explicit written permission** to test. Unauthorized scanning,
> brute-forcing, or exploitation of networks you do not control is illegal in most
> jurisdictions, and you alone are responsible for how you use them. Every script is
> scoped to a single target you pass on the command line.

## Scripts

| Script | What it does | Needs |
|---|---|---|
| `net-test.sh` | Connection health: interface/route, carrier, latency/loss/jitter, DNS, up/down speed, 30s stability | any connection |
| `wifi-audit.sh` | Wi-Fi posture: encryption/WPS/PMF recon, router service scan, handshake → passphrase test, WPS Pixie-Dust | monitor-mode adapter |
| `net-audit.sh` | Comprehensive: nmap recon, default-creds, RouterSploit autopwn, hydra brute-force, UPnP/SNMP, plus the full Wi-Fi radio audit | see below |

## Requirements

- Kali Linux (or Debian/Ubuntu), run as root.
- For the Wi-Fi/radio features: a USB adapter that supports **monitor mode + packet
  injection** (e.g. Realtek RTL8812AU/BU). Note that monitor-mode injection is unreliable
  inside a VM over USB passthrough — use a bare-metal install or a Raspberry Pi for the
  active radio attacks.

### Install the tooling
```bash
sudo apt update && sudo apt install -y \
  aircrack-ng reaver bully hcxtools hcxdumptool \
  nmap hydra exploitdb snmp onesixtyone miniupnpc routersploit
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz   # wordlist for offline cracks
```

## Usage

### net-test.sh — connection health
```bash
./net-test.sh                 # test the current connection
./net-test.sh 8.8.8.8         # ping/measure against a specific host
```

### wifi-audit.sh — Wi-Fi security
```bash
sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi"            # passive: encryption + WPS
sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi" --router   # + scan the router
sudo ./wifi-audit.sh -i wlan0 -s "MyHomeWiFi" --active   # + passphrase + WPS tests
```

### net-audit.sh — comprehensive router + Wi-Fi audit
```bash
# router side (works over a normal connection):
sudo ./net-audit.sh -t auto --exploit --brute --upnp
# everything including the radio layer (needs injection):
sudo ./net-audit.sh -t auto -s "MyHomeWiFi" -i wlan0 --all
```

All three write a timestamped report to your home directory.

## Checks at a glance
- **Encryption** — flags Open / WEP / WPA1 (bad), WPA2-only (needs a strong key), WPA3 (good)
- **WPS** — detects enabled/unlocked → Pixie-Dust / PIN brute-force exposure
- **Passphrase strength** — captures a handshake or PMKID and tests it against a wordlist
- **Router** — nmap service/version, telnet / TR-069 / UPnP / SNMP exposure, default
  credentials, known-exploit scan (RouterSploit autopwn), credential brute-force (hydra)

## License
MIT — see [LICENSE](LICENSE).

## Disclaimer
Provided for educational and authorized security-assessment purposes only, with no
warranty of any kind. The author accepts no liability for misuse or for any damage
caused by these tools.

## wifi-crack.sh — end-to-end WPA audit (one command)

Chains the whole workflow with a timestamped progress log: monitor mode → scan &
resolve target → confirm injection + WPS → capture the 4-way handshake (auto-deauth,
with a radio reset if the USB adapter wedges) → build a wordlist → `aircrack-ng`.

```bash
# dictionary attack with rockyou:
sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi"
# targeted wordlist generated from keywords (+ numbers):
sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi" -k "john home city 1990 1234"
# just capture the handshake, no crack:
sudo ./wifi-crack.sh -i wlan0 -s "MyWiFi" --no-crack
```

Artifacts (handshake, wordlist, logs, `RESULT.txt`) are written to a timestamped
`wifi-crack-*/` directory. `-h` prints full options. Authorised / own-network use only.
