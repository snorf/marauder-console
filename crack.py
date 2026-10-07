"""Convert a capture to a hashcat 22000 hash and run a dictionary attack.

Thin wrappers around the external tools hcxpcapngtool and hashcat. Cracking a
handshake only recovers a password for WPA2/WPA3-Personal (PSK) networks.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        raise RuntimeError(f"'{tool}' hittades inte i PATH (installera det först).")


def latest_pcap(captures_dir) -> Path | None:
    pcaps = sorted(Path(captures_dir).glob("*.pcap"))
    return pcaps[-1] if pcaps else None


def convert(pcap, hashfile=None) -> Path | None:
    """Run hcxpcapngtool; return the hash file if it got any crackable rows."""
    _require("hcxpcapngtool")
    pcap = Path(pcap)
    hashfile = Path(hashfile) if hashfile else pcap.with_suffix(".hc22000")
    subprocess.run(["hcxpcapngtool", "-o", str(hashfile), str(pcap)], check=False)
    if hashfile.exists() and hashfile.stat().st_size > 0:
        return hashfile
    return None


def crack(hashfile, wordlist) -> None:
    """Run hashcat -m 22000 against a wordlist, then print any recovered keys."""
    _require("hashcat")
    subprocess.run(
        ["hashcat", "-m", "22000", str(hashfile), str(wordlist), "-w", "3"],
        check=False,
    )
    print("\n=== Återfunna nycklar (hashcat --show) ===")
    subprocess.run(["hashcat", "-m", "22000", str(hashfile), "--show"], check=False)
