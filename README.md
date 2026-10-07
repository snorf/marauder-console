# Marauder Console

A small terminal front-end (Python) for the **ESP32 Marauder** firmware running
on a Flipper Zero WiFi dev board. It drives Marauder's serial CLI so you can
scan, pick a target, capture a WPA handshake/PMKID, and convert + crack it — all
from your laptop instead of the Flipper's little screen.

It does nothing the Marauder firmware doesn't already do; it's a convenience
wrapper and a homage to [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)
by *justcallmekoko*.

## ⚠️ Authorized use only

This tool captures WPA handshakes and can transmit **deauthentication** frames.
Only use it against networks you **own or are explicitly authorized to test**.
Deauthing or capturing traffic on networks you don't control is illegal in most
jurisdictions. You are responsible for how you use it. Know your local laws.

## Hardware

- Flipper Zero **WiFi dev board** (ESP32-S2) flashed with **ESP32 Marauder**
  (tested with v1.17.0), or a compatible ESP32 Marauder board.
- Connect either via the Flipper's **USB-UART bridge** (`Apps > GPIO >
  USB-UART Bridge`, 115200 baud) or the dev board's own USB-C.
- The board needs serial pcap support (the `-serial` flag); the official
  dev-board Marauder builds have it.

## Requirements

- Python 3.10+
- [`pyserial`](https://pypi.org/project/pyserial/) (`requirements.txt`)
- For cracking: [`hcxtools`](https://github.com/ZerBea/hcxtools)
  (`hcxpcapngtool`) and [`hashcat`](https://hashcat.net/hashcat/)

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Usage

```bash
.venv/bin/python menu.py                 # auto-detect port, English UI
.venv/bin/python menu.py --lang sv       # Swedish UI
.venv/bin/python menu.py --port /dev/cu.usbmodemXXXX
MARAUDER_LANG=sv .venv/bin/python menu.py
```

Menu:

```
[1] Scan networks (passive)
[2] Show found networks
[3] Select targets (index: 0,3,5 · all · none)
[4] Capture handshake/PMKID — passive
[5] Capture handshake/PMKID — with deauth (your own net only)
[6] Reboot the board
[7] Convert + crack latest capture
[8] Find clients' AP/channel (+ select)
[0] Quit
```

**Typical flow:** `8` (find which of your APs has a client, and on which
channel — it selects the target for you) → `5` (deauth capture to force the
handshake) → `7` (convert + crack). Captures land in `captures/` as `.pcap`.

Notes:
- Only **one** instance can hold the serial port at a time.
- The deauth flag is sticky in firmware; the tool reboots the board after a
  deauth capture to clear it.
- Cracking only recovers a key for **WPA2/WPA3-Personal (PSK)**. WPA-Enterprise
  (802.1X) has no shared key, and WPA3-SAE resists offline dictionary attacks.
  PMF (802.11w) makes deauth ineffective — use passive/PMKID capture there.

## Cracking

`captures/*.hc22000` is a plain hashcat file; crack it anywhere:

```bash
hcxpcapngtool -o hash.hc22000 captures/your_capture.pcap
hashcat -m 22000 hash.hc22000 /path/to/wordlist.txt
```

Option `7` does this for you against a wordlist (default `rockyou.txt` in the
project folder if present). A machine with NVIDIA GPUs is much faster — copy the
`.hc22000` over and run hashcat there; it uses all GPUs automatically.

## Translations

The UI is fully localized. Each language is a JSON file in `locales/`
(`en.json`, `sv.json`, …), discovered automatically. To add one:

1. Copy `locales/en.json` to `locales/<code>.json` (e.g. `de.json`).
2. Translate the values (keep the keys and `{placeholders}` intact).
3. Run with `--lang <code>` and open a PR. 🙌

Missing keys fall back to English, so partial translations still work.

## Project layout

```
menu.py          text UI (theme, menu, flows)
tui.py           ANSI theming, banner, matrix intro, input helpers
marauder.py      Marauder CLI API (scan/list/select/capture) + port auto-detect
transport.py     serial I/O
pcap_capture.py  de-frames the [BUF/BEGIN]..[BUF/CLOSE] serial pcap stream
crack.py         hcxpcapngtool + hashcat wrappers
i18n.py          JSON message catalogs
locales/         language files
```

## Credits

- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) — the
  firmware this talks to.
- [hcxtools](https://github.com/ZerBea/hcxtools) and
  [hashcat](https://hashcat.net/) — conversion and cracking.

## License

MIT — see [LICENSE](LICENSE).
