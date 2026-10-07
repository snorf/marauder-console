"""Tiny JSON-based i18n.

Each language is a file locales/<code>.json mapping message keys to strings.
To add a language, drop in a new file with the same keys (see locales/en.json)
-- it is discovered automatically. Missing keys fall back to English.
"""
from __future__ import annotations

import json
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "locales"
_FALLBACK = "en"
_cache: dict[str, dict] = {}
_lang = _FALLBACK


def available() -> list[str]:
    if not _DIR.is_dir():
        return [_FALLBACK]
    return sorted(p.stem for p in _DIR.glob("*.json"))


def _load(code: str) -> dict:
    if code not in _cache:
        try:
            _cache[code] = json.loads((_DIR / f"{code}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _cache[code] = {}
    return _cache[code]


def set_lang(code) -> str:
    global _lang
    code = (code or "").lower()
    _lang = code if code in available() else _FALLBACK
    return _lang


def current() -> str:
    return _lang


def t(key: str, **kw) -> str:
    msg = _load(_lang).get(key)
    if msg is None:
        msg = _load(_FALLBACK).get(key, key)
    try:
        return msg.format(**kw) if kw else msg
    except (KeyError, IndexError, ValueError):
        return msg
