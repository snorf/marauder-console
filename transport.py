"""Serial transport for the ESP32 Marauder CLI.

Talks to the Marauder command line over the Flipper's USB-UART bridge (or the
dev board's own USB). The CLI is line-based at 115200 8N1: a command is sent as
`<cmd>\\n`, the device echoes `#<cmd>`, prints output, then a `> ` prompt.
"""
from __future__ import annotations

import time

import serial


class Transport:
    """Thin, synchronous wrapper around a Marauder serial port."""

    def __init__(self, port: str, baud: int = 115200, open_now: bool = True):
        self._ser = serial.Serial()
        self._ser.port = port
        self._ser.baudrate = baud
        self._ser.bytesize = serial.EIGHTBITS
        self._ser.parity = serial.PARITY_NONE
        self._ser.stopbits = serial.STOPBITS_ONE
        self._ser.timeout = 0.2
        # Keep ESP32 auto-reset lines idle so opening the port can't reboot it.
        self._ser.dtr = False
        self._ser.rts = False
        if open_now:
            self.open()

    # -- lifecycle -----------------------------------------------------------
    def open(self) -> None:
        if not self._ser.is_open:
            self._ser.open()
            time.sleep(0.3)
            self.drain(0.5)

    def close(self) -> None:
        if self._ser.is_open:
            self._ser.close()

    def __enter__(self) -> "Transport":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- raw I/O -------------------------------------------------------------
    def drain(self, seconds: float) -> None:
        """Discard whatever is on the line for `seconds`."""
        end = time.time() + seconds
        while time.time() < end:
            self._ser.read(4096)

    def write_line(self, cmd: str) -> None:
        self._ser.reset_input_buffer()
        self._ser.write((cmd + "\n").encode())
        self._ser.flush()

    def read_quiet(self, idle: float = 0.6, hard: float = 5.0) -> bytes:
        """Read until the line is quiet for `idle` s, or `hard` s elapse."""
        buf = bytearray()
        start = last = time.time()
        while True:
            chunk = self._ser.read(4096)
            if chunk:
                buf += chunk
                last = time.time()
            elif time.time() - last > idle:
                break
            if time.time() - start > hard:
                break
        return bytes(buf)

    def read_for(self, seconds: float) -> bytes:
        """Read everything arriving over a fixed window (for live scans)."""
        buf = bytearray()
        end = time.time() + seconds
        while time.time() < end:
            chunk = self._ser.read(4096)
            if chunk:
                buf += chunk
        return bytes(buf)

    def stream(self, seconds: float, on_chunk) -> None:
        """Read for `seconds`, passing each raw chunk to on_chunk(bytes)."""
        end = time.time() + seconds
        while time.time() < end:
            chunk = self._ser.read(4096)
            if chunk:
                on_chunk(chunk)

    # -- command/response ----------------------------------------------------
    def command(self, cmd: str, idle: float = 0.6, hard: float = 5.0) -> str:
        """Send a short command and return its reply, echo and prompt stripped."""
        self.write_line(cmd)
        return self._clean(cmd, self.read_quiet(idle, hard))

    @staticmethod
    def _clean(cmd: str, raw: bytes) -> str:
        cleaned = []
        for line in raw.decode(errors="replace").splitlines():
            stripped = line.strip()
            if stripped == f"#{cmd}" or stripped in ("", ">"):
                continue
            if line.startswith("> "):
                line = line[2:]
            cleaned.append(line.rstrip())
        return "\n".join(cleaned)
