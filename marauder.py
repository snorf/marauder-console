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

# Live `scanall` AP line, e.g. "-70 Ch: 6 10:a8:29:7b:d7:a1 ESSID: Bostner24 31 11"
_AP_STREAM_RE = re.compile(
    r"^-?(\d+)\s+Ch:\s*(\d+)\s+([0-9a-fA-F:]{17})\s+ESSID:\s*(.*?)(?:\s+\d+\s+\d+)?\s*$"
)
# Station<->AP link line, e.g. "1: sta: 20:0d:3d:73:05:0f -> ap: 10:a8:29:7b:d7:a1"
_MAC_RE = re.compile(r"(sta|ap):\s*([0-9a-fA-F:]{17})")


def _is_unicast(mac: str) -> bool:
    """True for a real station MAC; False for multicast/broadcast group MACs."""
    try:
        return int(mac.split(":")[0], 16) & 1 == 0
    except ValueError:
        return False


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

    def select_ssid_on_channel(self, ssid: str, channel: int) -> tuple[list[int], list[int]]:
        """Select every AP matching ssid+channel. Returns (wanted, selected).

        `list -a` exposes no BSSID, so we target by SSID+channel -- selecting
        all radios of that network on the client's channel.
        """
        want = sorted(ap.index for ap in self.list_aps()
                      if ap.ssid == ssid and ap.channel == channel)
        for idx in want:
            self.select_ap(idx)
        got = sorted(ap.index for ap in self.list_aps() if ap.selected)
        return want, got

    # -- station discovery ---------------------------------------------------
    def scan_stations(self, seconds: float = 20.0) -> tuple[dict, list]:
        """Run `scanall` and parse its live stream.

        Returns (bssids, links): bssids maps a BSSID to {channel, essid};
        links is a list of (station_mac, ap_bssid) association pairs.
        """
        self.t.write_line("scanall")
        text = self.t.read_for(seconds).decode(errors="replace")
        self.stop()
        bssids: dict = {}
        links: list = []
        for line in text.splitlines():
            m = _AP_STREAM_RE.match(line.strip())
            if m:
                _, ch, bssid, essid = m.groups()
                bssids[bssid.lower()] = {"channel": int(ch), "essid": essid.strip()}
                continue
            macs = {kind: mac.lower() for kind, mac in _MAC_RE.findall(line)}
            if "sta" in macs and "ap" in macs:
                links.append((macs["sta"], macs["ap"]))
        return bssids, links

    def clients_by_network(self, seconds: float = 20.0) -> list:
        """[[essid, channel, [client_macs]], ...] for networks with clients."""
        bssids, links = self.scan_stations(seconds)
        agg: dict = {}
        for sta, ap in links:
            if not _is_unicast(sta):
                continue  # drop multicast/broadcast destinations -- not real clients
            info = bssids.get(ap)
            if info is None:
                continue
            agg.setdefault((info["essid"], info["channel"]), set()).add(sta)
        return sorted(
            ([essid, ch, sorted(macs)] for (essid, ch), macs in agg.items()),
            key=lambda row: (-len(row[2]), row[0]),
        )

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
