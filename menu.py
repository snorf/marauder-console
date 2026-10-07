#!/usr/bin/env python3
"""Simple text menu for the ESP32 Marauder wrapper.

Scoped to testing your OWN network: scan, pick your target, capture a
handshake/PMKID to a local .pcap, and (as an explicit opt-in) force the
capture with a deauth of your own AP.
"""
import sys
from pathlib import Path

from crack import convert, crack, latest_pcap
from marauder import Marauder
from pcap_capture import PCAP_MAGICS, save_pcap

PORT_DEFAULT = "/dev/cu.usbmodemflip_V44llle1"
CAPTURES_DIR = Path(__file__).resolve().parent / "captures"
WORDLIST_DEFAULT = Path(__file__).resolve().parent / "rockyou.txt"


def ask_int(prompt, default=None):
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def show_aps(aps):
    if not aps:
        print("  (inga nät i listan — kör en scan först)")
        return
    for ap in aps:
        mark = "  *VALD*" if ap.selected else ""
        print(f"  [{ap.index:>2}] ch{ap.channel:>2}  {ap.rssi:>4} dBm  {ap.ssid}{mark}")


def report_status(text):
    for line in text.splitlines():
        s = line.strip()
        if s and ("EAPOL" in s or "PMKID" in s or s.startswith("Starting")):
            print("   " + s)


def do_capture(m, deauth):
    selected = [ap for ap in m.list_aps() if ap.selected]
    if len(selected) != 1:
        print("Välj exakt ETT mål (ditt eget nät) först — alternativ 3.")
        return
    target = selected[0]
    print(f"Mål: [{target.index}] {target.ssid}  ch{target.channel}  {target.rssi} dBm")
    kind = "AKTIV deauth-capture" if deauth else "passiv capture"
    if input(f"Bekräfta att '{target.ssid}' är DITT nät och kör {kind}? (ja/nej): ").strip().lower() != "ja":
        print("Avbrutet.")
        return
    secs = ask_int("Sekunder [30]: ", 30)
    print(f"Fångar {secs}s på kanal {target.channel} ... (Ctrl-C avbryter)")
    try:
        pcap, _ = m.capture_pmkid(channel=target.channel, targeted=True,
                                  deauth=deauth, seconds=secs, on_text=report_status)
    except KeyboardInterrupt:
        pcap = b""
        m.stop()
        print("\nAvbrutet av användaren.")
    finally:
        if deauth:
            print("Deauth användes — startar om kortet för att nolla sändflaggan ...")
            m.reboot()

    if pcap[:4] in PCAP_MAGICS:
        path = save_pcap(pcap)
        print(f"Sparade {len(pcap)} byte pcap: {path}")
        print(f"Knäck offline (din fil): hcxpcapngtool -o hash.hc22000 '{path}' "
              f"&& hashcat -m 22000 hash.hc22000 <ordlista>")
    else:
        print(f"Ingen giltig pcap ({len(pcap)} byte) — ingen handshake/PMKID sågs i fönstret.")


def do_convert_crack():
    pcap = latest_pcap(CAPTURES_DIR)
    if pcap is None:
        print("Ingen capture i captures/. Fånga en handshake först (alt 4/5).")
        return
    print(f"Senaste capture: {pcap.name}")
    try:
        hashfile = convert(pcap)
    except RuntimeError as exc:
        print(exc)
        return
    if hashfile is None:
        print("Ingen knäckbar hash kunde extraheras (ingen handshake/PMKID i filen).")
        return
    print(f"Hash: {hashfile}")
    default = WORDLIST_DEFAULT if WORDLIST_DEFAULT.exists() else None
    prompt = f"Ordlista [{default}]: " if default else "Ordlista (sökväg): "
    raw = input(prompt).strip()
    wordlist = Path(raw) if raw else default
    if wordlist is None or not wordlist.exists():
        print(f"Ordlistan finns inte: {wordlist}")
        return
    try:
        crack(hashfile, wordlist)
    except RuntimeError as exc:
        print(exc)


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else PORT_DEFAULT
    with Marauder(port) as m:
        info = m.info()
        print(f"Ansluten: Marauder {info.get('Version')} på {info.get('Hardware')} "
              f"| SD: {info.get('SD Card')}")
        while True:
            print("\n=== Marauder (eget nät) ===")
            print(" 1) Scanna nätverk (passivt)")
            print(" 2) Visa hittade nät")
            print(" 3) Välj/avvälj mål (toggle)")
            print(" 4) Fånga handshake/PMKID — passivt")
            print(" 5) Fånga handshake/PMKID — med deauth (endast ditt nät)")
            print(" 6) Starta om kortet")
            print(" 7) Konvertera + knäck senaste capturen")
            print(" 0) Avsluta")
            choice = input("> ").strip()
            if choice == "1":
                secs = ask_int("Sekunder [12]: ", 12)
                print(f"Skannar {secs}s ...")
                m.scan_all(secs)
                show_aps(m.list_aps())
            elif choice == "2":
                show_aps(m.list_aps())
            elif choice == "3":
                show_aps(m.list_aps())
                idx = ask_int("Index att toggla: ")
                if idx is not None:
                    m.select_ap(idx)
                    show_aps(m.list_aps())
            elif choice == "4":
                do_capture(m, deauth=False)
            elif choice == "5":
                do_capture(m, deauth=True)
            elif choice == "6":
                m.reboot()
                print("Omstartad.")
            elif choice == "7":
                do_convert_crack()
            elif choice == "0":
                m.stop()
                print("Hej då!")
                break
            else:
                print("Okänt val.")


if __name__ == "__main__":
    main()
