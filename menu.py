#!/usr/bin/env python3
"""Text menu for the ESP32 Marauder wrapper (green 'haxxor' theme).

Scoped to testing your OWN network: scan, pick your target, capture a
handshake/PMKID to a local .pcap, and (as an explicit opt-in) force the
capture with a deauth of your own AP. UI language is pluggable (see i18n).
"""
import argparse
import os
import sys
import threading
import time
from pathlib import Path

import crack
import i18n
import marauder as marauder_mod
import tui
from i18n import t
from marauder import Marauder
from pcap_capture import PCAP_MAGICS, save_pcap

CAPTURES_DIR = Path(__file__).resolve().parent / "captures"
WORDLIST_DEFAULT = Path(__file__).resolve().parent / "rockyou.txt"

MENU_KEYS = [
    ("1", "menu.scan"), ("2", "menu.show"), ("3", "menu.select"),
    ("4", "menu.cap_passive"), ("5", "menu.cap_deauth"), ("6", "menu.reboot"),
    ("7", "menu.crack"), ("8", "menu.find"), ("0", "menu.quit"),
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
        tui.line(t("aps.empty"), tui.DIM)
        return
    for ap in aps:
        mark = tui.c(t("aps.selected_tag"), tui.BGREEN) if ap.selected else ""
        tui.line(f"  [{ap.index:>2}] ch{ap.channel:>2}  {ap.rssi:>4} dBm  {ap.ssid}" + mark)


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
                tui.status(t("status.countdown", label=label, left=f"{left:4.1f}", dots=dots))
            else:
                tui.status(t("status.fetching", label=label, dots=dots), tui.GREEN)
            time.sleep(0.1)

    th = threading.Thread(target=tick, daemon=True)
    th.start()
    try:
        return work()
    finally:
        stop.set()
        th.join(timeout=0.3)
        tui.end_status()


def do_select(m):
    aps = m.list_aps()
    if not aps:
        tui.line(t("aps.none_scan"), tui.DIM)
        return
    show_aps(aps)
    raw = tui.prompt(t("select.prompt"))
    if not raw.strip():
        tui.line(t("common.cancelled"), tui.DIM)
        return
    desired, err = tui.parse_indexes(raw, {ap.index for ap in aps})
    if err:
        code, data = err
        tui.line(t("err.unknown_index", bad=data) if code == "unknown_index"
                 else t("err.bad_input"), tui.RED)
        return
    changed = 0
    for ap in aps:
        if (ap.index in desired) != ap.selected:
            m.select_ap(ap.index)
            changed += 1
    tui.line(t("select.done", n=len(desired), changed=changed), tui.BGREEN)
    show_aps(m.list_aps())


def do_capture(m, deauth):
    selected = [ap for ap in m.list_aps() if ap.selected]
    if not selected:
        tui.line(t("cap.no_target"), tui.RED)
        return
    channels = sorted({ap.channel for ap in selected})
    if len(channels) > 1:
        tui.line(t("cap.multi_channel", channels=channels), tui.RED)
        return
    channel = channels[0]
    ssids = ", ".join(sorted({ap.ssid for ap in selected}))
    tui.line(t("cap.target", ssids=ssids, channel=channel, n=len(selected)), tui.BGREEN)
    if deauth:
        tui.line(t("cap.deauth_warn"), tui.RED)
    kind = t("cap.kind_deauth") if deauth else t("cap.kind_passive")
    answer = tui.prompt(t("cap.confirm", kind=kind)).strip().lower()
    if answer not in (set(t("confirm.yes").split()) | {"yes", "y"}):
        tui.line(t("common.cancelled"), tui.DIM)
        return
    secs = ask_int(t("cap.secs_prompt", default=30), 30)
    tui.line(t("cap.capturing", secs=secs, channel=channel), tui.GREEN)
    pcap = b""
    state = {"eapol": 0, "start": time.time()}
    stop = threading.Event()

    def on_text(text):
        state["eapol"] += text.count("Received EAPOL")

    def tick():
        # Time-driven, so the elapsed clock keeps moving even while the serial
        # line is quiet (the board is still working during a deauth capture).
        while not stop.is_set():
            elapsed = time.time() - state["start"]
            tui.status(t("status.capture", elapsed=f"{elapsed:5.1f}", total=secs,
                         eapol=state["eapol"]))
            time.sleep(0.2)

    ticker = threading.Thread(target=tick, daemon=True)
    live = sys.stdout.isatty()
    if live:
        ticker.start()
    try:
        pcap, _ = m.capture_pmkid(channel=channel, targeted=True,
                                  deauth=deauth, seconds=secs, on_text=on_text)
    except KeyboardInterrupt:
        m.stop()
        tui.line("\n" + t("cap.aborted"), tui.DIM)
    finally:
        stop.set()
        if live:
            ticker.join(timeout=0.3)
        tui.end_status()
        if deauth:
            tui.line(t("cap.deauth_reboot"), tui.DIM)
            m.reboot()

    if pcap[:4] in PCAP_MAGICS:
        path = save_pcap(pcap)
        tui.line(t("cap.saved", n=len(pcap), path=path), tui.BGREEN)
        tui.line(t("cap.crack_hint", path=path), tui.DIM)
    else:
        tui.line(t("cap.none", n=len(pcap)), tui.RED)


def do_convert_crack():
    pcap = crack.latest_pcap(CAPTURES_DIR)
    if pcap is None:
        tui.line(t("crack.no_capture"), tui.RED)
        return
    tui.line(t("crack.latest", name=pcap.name), tui.GREEN)
    try:
        hashfile = crack.convert(pcap)
    except crack.MissingTool as exc:
        tui.line(t("err.tool_missing", tool=exc.tool), tui.RED)
        return
    if hashfile is None:
        tui.line(t("crack.no_hash"), tui.RED)
        return
    tui.line(t("crack.hash", path=hashfile), tui.BGREEN)
    default = WORDLIST_DEFAULT if WORDLIST_DEFAULT.exists() else None
    label = t("crack.wordlist_default", default=default) if default else t("crack.wordlist_prompt")
    raw = tui.prompt(label).strip()
    wordlist = Path(raw) if raw else default
    if wordlist is None or not wordlist.exists():
        tui.line(t("crack.wordlist_missing", path=wordlist), tui.RED)
        return
    try:
        crack.crack(hashfile, wordlist, show_label=t("crack.recovered_header"))
    except crack.MissingTool as exc:
        tui.line(t("err.tool_missing", tool=exc.tool), tui.RED)


def do_find_clients(m):
    secs = ask_int(t("find.secs_prompt", default=20), 20)
    rows = _countdown(t("status.station_scan"), secs, lambda: m.clients_by_network(secs))
    if not rows:
        tui.line(t("find.none"), tui.DIM)
        return
    tui.line(t("find.header"), tui.BGREEN)
    for essid, ch, macs in rows:
        tui.line(t("find.row", essid=essid, ch=ch, n=len(macs), macs=", ".join(macs)))
    print()
    essid = tui.prompt(t("find.select_prompt")).strip()
    if not essid:
        return
    ch = ask_int(t("find.channel_prompt"))
    if ch is None:
        return
    want, got = m.select_ssid_on_channel(essid, ch)
    if not want:
        tui.line(t("find.not_found", essid=essid, ch=ch), tui.RED)
    elif got == want:
        tui.line(t("find.selected", essid=essid, ch=ch, got=got), tui.BGREEN)
    else:
        tui.line(t("find.mismatch", got=got, want=want), tui.RED)


def render_menu():
    tui.line("┌─[ M A R A U D E R ]" + "─" * 28, tui.GREEN)
    for key, msgkey in MENU_KEYS:
        tui.line("│ " + tui.c(f"[{key}]", tui.BGREEN) + " " + tui.c(t(msgkey), tui.GREEN))
    tui.line("└" + "─" * 47, tui.GREEN)


def main():
    parser = argparse.ArgumentParser(
        description="ESP32 Marauder terminal console (own-network testing).")
    parser.add_argument("--port", help="serial port (default: auto-detect)")
    parser.add_argument("--lang", help="UI language: " + ", ".join(i18n.available()))
    parser.add_argument("port_pos", nargs="?", help=argparse.SUPPRESS)
    args = parser.parse_args()

    i18n.set_lang(args.lang or os.environ.get("MARAUDER_LANG"))
    port = args.port or args.port_pos or marauder_mod.find_port()

    tui.intro()
    if not port:
        tui.line(t("app.no_port"), tui.RED)
        return
    with Marauder(port) as m:
        info = m.info()
        tui.line(t("link", ver=info.get("Version"), hw=info.get("Hardware"),
                   sd=info.get("SD Card")), tui.BGREEN)
        while True:
            print()
            render_menu()
            choice = tui.prompt("> ").strip()
            if choice == "1":
                secs = ask_int(t("cap.secs_prompt", default=12), 12)
                _countdown(t("status.scanning"), secs, lambda: m.scan_all(secs))
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
                tui.line(t("board.rebooted"), tui.GREEN)
            elif choice == "7":
                do_convert_crack()
            elif choice == "8":
                do_find_clients(m)
            elif choice == "0":
                m.stop()
                tui.line(t("app.link_down"), tui.BGREEN)
                break
            else:
                tui.line(t("app.unknown_choice"), tui.RED)


if __name__ == "__main__":
    main()
