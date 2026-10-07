"""De-frame Marauder's serial pcap stream.

With the `-serial` flag, Marauder sends captured packets as
`[BUF/BEGIN]<raw pcap bytes>[BUF/CLOSE]` blocks, interleaved with ASCII status
text. Concatenating the block payloads in order yields a valid .pcap file.
"""
from __future__ import annotations

import time
from pathlib import Path

BEGIN = b"[BUF/BEGIN]"
CLOSE = b"[BUF/CLOSE]"
PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanosecond
)


class PcapDeframer:
    """Split a mixed serial stream into pcap bytes and out-of-band text.

    Feed it chunks as they arrive; markers may be split across chunks.
    """

    def __init__(self):
        self._buf = bytearray()
        self.pcap = bytearray()
        self.text = bytearray()

    def feed(self, data: bytes) -> None:
        self._buf += data
        self._drain(flush=False)

    def finish(self) -> None:
        self._drain(flush=True)

    def _drain(self, flush: bool) -> None:
        while True:
            begin = self._buf.find(BEGIN)
            if begin == -1:
                # No complete BEGIN marker. Flush to text, but (unless we're
                # finishing) hold back a tail that could be a split marker.
                keep = 0 if flush else len(BEGIN) - 1
                cut = len(self._buf) - keep
                if cut > 0:
                    self.text += self._buf[:cut]
                    del self._buf[:cut]
                return
            # Text before the block belongs to the status stream.
            self.text += self._buf[:begin]
            del self._buf[:begin]  # buffer now starts with BEGIN
            close = self._buf.find(CLOSE, len(BEGIN))
            if close == -1:
                return  # wait for the closing marker
            self.pcap += self._buf[len(BEGIN):close]
            del self._buf[:close + len(CLOSE)]

    @property
    def looks_like_pcap(self) -> bool:
        return bytes(self.pcap[:4]) in PCAP_MAGICS


def save_pcap(data: bytes, directory: str | None = None, prefix: str = "capture") -> Path:
    # Default to a captures/ dir next to this module, so the output location
    # does not depend on the current working directory.
    out_dir = Path(directory) if directory else Path(__file__).resolve().parent / "captures"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
    path.write_bytes(data)
    return path
