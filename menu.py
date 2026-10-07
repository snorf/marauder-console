#!/usr/bin/env python3
"""Text menu for the ESP32 Marauder wrapper (green 'haxxor' theme).

Scoped to testing your OWN network: scan, pick your target, capture a
handshake/PMKID to a local .pcap, and (as an explicit opt-in) force the
capture with a deauth of your own AP.
"""
import sys
import threading
import time
from pathlib import Path

import tui
from crack import convert, crack, latest_pcap
from marauder import Marauder
from pcap_capture import PCAP_MAGICS, save_pcap

PORT_DEFAULT = "/dev/cu.usbmodemflip_V44llle1"
CAPTURES_DIR = Path(__file__).resolve().parent / "captures"
WORDLIST_DEFAULT = Path(__file__).resolve().parent / "rockyou.txt"

MENU_ITEMS = [
    ("1", "Scanna nätverk (passivt)"),
    ("2", "Visa hittade nät"),
    ("3", "Välj mål (index: 0,3,5 · all · none)"),
    ("4", "Fånga handshake/PMKID — passivt"),
    ("5", "Fånga handshake/PMKID — med deauth (endast ditt nät)"),
    ("6", "Starta om kortet"),
    ("7", "Konvertera + knäck senaste capturen"),
    ("8", "Hitta klienters AP/kanal (+välj mål)"),
    ("0", "Avsluta"),
]


def ask_int(label, default=None):
    raw = tui.prompt(label).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def show_aps(aps):
    if not aps:
        tui.line("  (inga nät i listan — kör en scan först)", tui.DIM)
        return
    for ap in aps:
        mark = tui.c("  ◄ VALD", tui.BGREEN) if ap.selected else ""
        tui.line(f"  [{ap.index:>2}] ch{ap.channel:>2}  {ap.rssi:>4} dBm  {ap.ssid}" + mark)


def do_select(m):
    aps = m.list_aps()
    if not aps:
        tui.line("Inga nät — kör en scan först (alt 1).", tui.DIM)
        return
    show_aps(aps)
    raw = tui.prompt("Välj index (komma-separerat 0,3,5 · 'all' · 'none' · blankt=avbryt): ")
    if not raw.strip():
        tui.line("Avbrutet.", tui.DIM)
        return
    desired, err = tui.parse_indexes(raw, {ap.index for ap in aps})
    if err:
        tui.line(err, tui.RED)
        return
    # Apply as a diff so the selection becomes exactly `desired`.
    changed = 0
    for ap in aps:
        if (ap.index in desired) != ap.selected:
            m.select_ap(ap.index)
            changed += 1
    tui.line(f"✔ {len(desired)} mål valda ({changed} ändrade).", tui.BGREEN)
    show_aps(m.list_aps())


def _countdown(label, seconds, work):
    """Run blocking `work()` while showing an in-place countdown."""
    if not sys.stdout.isatty():
        return work()
    stop = threading.Event()

    def tick():
        start = time.time()
        while not stop.is_set():
            left = max(0.0, seconds - (time.time() - start))
            dots = "." * (int(time.time() * 4) % 4)
            if left > 0:
                tui.status(f"▓ {label} … {left:4.1f}s {dots}")
            else:
                tui.status(f"▓ {label} … hämtar resultat {dots}", tui.GREEN)
            time.sleep(0.1)

    th = threading.Thread(target=tick, daemon=True)
    th.start()
    try:
        return work()
    finally:
        stop.set()
        th.join(timeout=0.3)
        tui.end_status()


def _capture_reporter():
    state = {"eapol": 0, "start": time.time()}

    def report(text):
        state["eapol"] += text.count("Received EAPOL")
        elapsed = time.time() - state["start"]
        tui.status(f"⟳ capture {elapsed:5.1f}s │ EAPOL-ramar: {state['eapol']:>3}")

    return report


def do_capture(m, deauth):
    selected = [ap for ap in m.list_aps() if ap.selected]
    if not selected:
        tui.line("Inget mål valt — välj ditt nät först (alt 3, eller 8 väljer åt dig).", tui.RED)
        return
    channels = sorted({ap.channel for ap in selected})
    if len(channels) > 1:
        tui.line(f"Valda mål ligger på flera kanaler {channels} — välj EN kanal (klientens).", tui.RED)
        return
    channel = channels[0]
    ssids = ", ".join(sorted({ap.ssid for ap in selected}))
    tui.line(f"Mål: {ssids}  ch{channel}  ({len(selected)} AP)", tui.BGREEN)
    if deauth:
        tui.line("⚠ AKTIV DEAUTH — kortet sänder mot ditt valda AP. Endast ditt eget nät.", tui.RED)
    kind = "AKTIV deauth-capture" if deauth else "passiv capture"
    if tui.prompt(f"Bekräfta att detta är DITT nät och kör {kind}? (ja/nej): ").strip().lower() != "ja":
        tui.line("Avbrutet.", tui.DIM)
        return
    secs = ask_int("Sekunder [30]: ", 30)
    tui.line(f"Fångar {secs}s på kanal {channel} … (Ctrl-C avbryter)", tui.GREEN)
    reporter = _capture_reporter()
    pcap = b""
    try:
        pcap, _ = m.capture_pmkid(channel=channel, targeted=True,
                                  deauth=deauth, seconds=secs, on_text=reporter)
    except KeyboardInterrupt:
        m.stop()
        tui.line("\nAvbrutet av användaren.", tui.DIM)
    finally:
        tui.end_status()
        if deauth:
            tui.line("Deauth användes — startar om kortet för att nolla sändflaggan …", tui.DIM)
            m.reboot()

    if pcap[:4] in PCAP_MAGICS:
        path = save_pcap(pcap)
        tui.line(f"✔ Sparade {len(pcap)} byte pcap: {path}", tui.BGREEN)
        tui.line(f"  knäck: hcxpcapngtool -o hash.hc22000 '{path}' && hashcat -m 22000 hash.hc22000 <ordlista>", tui.DIM)
    else:
        tui.line(f"✘ Ingen giltig pcap ({len(pcap)} byte) — ingen handshake/PMKID i fönstret.", tui.RED)


def do_convert_crack():
    pcap = latest_pcap(CAPTURES_DIR)
    if pcap is None:
        tui.line("Ingen capture i captures/. Fånga en handshake först (alt 4/5).", tui.RED)
        return
    tui.line(f"Senaste capture: {pcap.name}", tui.GREEN)
    try:
        hashfile = convert(pcap)
    except RuntimeError as exc:
        tui.line(str(exc), tui.RED)
        return
    if hashfile is None:
        tui.line("Ingen knäckbar hash kunde extraheras (ingen handshake/PMKID i filen).", tui.RED)
        return
    tui.line(f"Hash: {hashfile}", tui.BGREEN)
    default = WORDLIST_DEFAULT if WORDLIST_DEFAULT.exists() else None
    label = f"Ordlista [{default}]: " if default else "Ordlista (sökväg): "
    raw = tui.prompt(label).strip()
    wordlist = Path(raw) if raw else default
    if wordlist is None or not wordlist.exists():
        tui.line(f"Ordlistan finns inte: {wordlist}", tui.RED)
        return
    try:
        crack(hashfile, wordlist)
    except RuntimeError as exc:
        tui.line(str(exc), tui.RED)


def do_find_clients(m):
    secs = ask_int("Scan-sekunder [20]: ", 20)
    rows = _countdown("station-scan", secs, lambda: m.clients_by_network(secs))
    if not rows:
        tui.line("Inga associerade klienter sågs. Väck en klient (t.ex. Ring Light) och försök igen.", tui.DIM)
        return
    tui.line("Nät med aktiva klienter:", tui.BGREEN)
    for essid, ch, macs in rows:
        tui.line(f"  {essid}  ch{ch}  {len(macs)} klient(er): {', '.join(macs)}")
    essid = tui.prompt("\nVälj mål-SSID att selektera (blankt = hoppa): ").strip()
    if not essid:
        return
    ch = ask_int("Kanal: ")
    if ch is None:
        return
    want, got = m.select_ssid_on_channel(essid, ch)
    if not want:
        tui.line(f"Hittade inga '{essid}' på ch{ch} i listan — kör en längre scan (alt 1).", tui.RED)
    elif got == want:
        tui.line(f"✔ Valde '{essid}' på ch{ch}: index {got}. Kör nu alt 4 (passiv) eller 5 (deauth).", tui.BGREEN)
    else:
        tui.line(f"Selektionen blev {got} men ville ha {want} — rensa och försök igen.", tui.RED)


def render_menu():
    tui.line("┌─[ M A R A U D E R ]" + "─" * 28, tui.GREEN)
    for key, label in MENU_ITEMS:
        tui.line("│ " + tui.c(f"[{key}]", tui.BGREEN) + " " + tui.c(label, tui.GREEN))
    tui.line("└" + "─" * 47, tui.GREEN)


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else PORT_DEFAULT
    tui.intro()
    with Marauder(port) as m:
        info = m.info()
        tui.line(f"◉ länk: Marauder {info.get('Version')} @ {info.get('Hardware')} "
                 f"│ SD: {info.get('SD Card')}", tui.BGREEN)
        while True:
            print()
            render_menu()
            choice = tui.prompt("> ").strip()
            if choice == "1":
                secs = ask_int("Sekunder [12]: ", 12)
                _countdown("scanning", secs, lambda: m.scan_all(secs))
                show_aps(m.list_aps())
            elif choice == "2":
                show_aps(m.list_aps())
            elif choice == "3":
                do_select(m)
            elif choice == "4":
                do_capture(m, deauth=False)
            elif choice == "5":
                do_capture(m, deauth=True)
            elif choice == "6":
                m.reboot()
                tui.line("Omstartad.", tui.GREEN)
            elif choice == "7":
                do_convert_crack()
            elif choice == "8":
                do_find_clients(m)
            elif choice == "0":
                m.stop()
                tui.line("// link down. 73!", tui.BGREEN)
                break
            else:
                tui.line("Okänt val.", tui.RED)


if __name__ == "__main__":
    main()
