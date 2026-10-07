"""High-level ESP32 Marauder API built on the serial transport.

Phase 1 scope: device info, settings, passive AP/station discovery, listing and
selecting access points. Nothing here transmits -- scanning is receive-only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from pcap_capture import PcapDeframer
from transport import Transport

# `list -a` row, e.g. "[3][CH:6] MyHomeWiFi -58 (selected)"
_AP_RE = re.compile(
    r"^\[(\d+)\]\[CH:(\d+)\]\s+(.*?)\s+(-?\d+)(\s+\(selected\))?\s*$"
)


@dataclass
class AccessPoint:
    index: int
    channel: int
    ssid: str
    rssi: int
    selected: bool


class Marauder:
    def __init__(self, port: str, baud: int = 115200):
        self.t = Transport(port, baud)

    def close(self) -> None:
        self.t.close()

    def __enter__(self) -> "Marauder":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- device state --------------------------------------------------------
    def info(self) -> dict:
        """Parse `info` into a dict (Firmware, Version, Hardware, SD Card, ...)."""
        out = {}
        for line in self.t.command("info").splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                out[key.strip()] = value.strip()
        return out

    def settings(self) -> dict:
        """Parse `settings` into {name: value} (values as raw strings)."""
        out, name = {}, None
        for line in self.t.command("settings", idle=0.8, hard=6.0).splitlines():
            line = line.strip()
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Value:") and name is not None:
                out[name] = line.split(":", 1)[1].strip()
                name = None
        return out

    # -- scan / list / select ------------------------------------------------
    def scan_all(self, seconds: float = 10.0) -> None:
        """Passive AP + station discovery for `seconds`, then stop."""
        self.t.write_line("scanall")
        self.t.read_for(seconds)
        self.stop()

    def list_aps(self) -> list[AccessPoint]:
        aps = []
        for line in self.t.command("list -a", idle=0.8, hard=6.0).splitlines():
            m = _AP_RE.match(line.strip())
            if m:
                aps.append(
                    AccessPoint(
                        index=int(m.group(1)),
                        channel=int(m.group(2)),
                        ssid=m.group(3),
                        rssi=int(m.group(4)),
                        selected=bool(m.group(5)),
                    )
                )
        return aps

    def clear_aps(self) -> None:
        self.t.command("clearlist -a")

    def select_ap(self, index: int) -> None:
        # Note: `select` TOGGLES; callers confirm state via list_aps().
        self.t.command(f"select -a {index}")

    # -- capture -------------------------------------------------------------
    def capture_pmkid(
        self,
        channel: int | None = None,
        targeted: bool = True,
        deauth: bool = False,
        seconds: float = 30.0,
        on_text=None,
    ) -> tuple[bytes, str]:
        """Capture PMKID/EAPOL and stream the pcap over serial.

        `targeted=True` (-l) captures only from the currently selected AP, so
        call select_ap() first. `deauth=True` (-d) actively transmits deauth
        frames at that AP to force a handshake -- only legitimate on your own
        network. Returns (pcap_bytes, status_text).
        """
        parts = ["sniffpmkid"]
        if channel is not None:
            parts.append(f"-c {channel}")
        if deauth:
            parts.append("-d")
        if targeted:
            parts.append("-l")
        parts.append("-serial")

        deframer = PcapDeframer()
        seen = 0

        def on_chunk(chunk: bytes) -> None:
            nonlocal seen
            deframer.feed(chunk)
            if on_text is not None and len(deframer.text) > seen:
                on_text(bytes(deframer.text[seen:]).decode(errors="replace"))
                seen = len(deframer.text)

        self.t.write_line(" ".join(parts))
        self.t.stream(seconds, on_chunk)
        deframer.finish()
        if on_text is not None and len(deframer.text) > seen:
            on_text(bytes(deframer.text[seen:]).decode(errors="replace"))
        self.stop()
        return bytes(deframer.pcap), deframer.text.decode(errors="replace")

    def reboot(self, wait: float = 6.0) -> None:
        """Restart the ESP32 (clears sticky flags such as send_deauth)."""
        self.t.write_line("reboot")
        self.t.read_for(wait)
        self.t.drain(0.5)

    def stop(self, force: bool = False) -> None:
        self.t.command("stopscan -f" if force else "stopscan", hard=4.0)


if __name__ == "__main__":
    import sys

    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbmodemflip_V44llle1"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

    with Marauder(port) as m:
        info = m.info()
        print(f"Firmware {info.get('Firmware')} {info.get('Version')} "
              f"on {info.get('Hardware')} | SD: {info.get('SD Card')}")
        s = m.settings()
        print(f"ForcePMKID={s.get('ForcePMKID')}  SavePCAP={s.get('SavePCAP')}  "
              f"ChanHop={s.get('ChanHop')}")

        print(f"\nScanning {secs:.0f}s (passive) ...")
        m.scan_all(secs)
        aps = m.list_aps()
        print(f"\nFound {len(aps)} access point(s):")
        for ap in aps:
            mark = " *" if ap.selected else ""
            print(f"  [{ap.index:>2}] ch{ap.channel:>2}  {ap.rssi:>4} dBm  {ap.ssid}{mark}")
