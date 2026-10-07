"""Green-on-black 'haxxor' theming for the menu.

Raw ANSI, no dependencies. Colour and animation auto-disable when stdout is
not a TTY (or NO_COLOR is set), so piping and redirection stay clean.
"""
from __future__ import annotations

import os
import random
import shutil
import sys
import time

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _e(code: str) -> str:
    return code if _TTY else ""


RESET = _e("\033[0m")
GREEN = _e("\033[32m")
BGREEN = _e("\033[92m")       # bright green
DIM = _e("\033[2;32m")
BOLD = _e("\033[1m")
RED = _e("\033[91m")
_HIDE = _e("\033[?25l")
_SHOW = _e("\033[?25h")

_ART = [
    "█▀▄▀█ ▄▀█ █▀█ ▄▀█ █ █ █▀▄ █▀▀ █▀█",
    "█ ▀ █ █▀█ █▀▄ █▀█ █▄█ █▄▀ █▄▄ █▀▄",
]


def width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def c(text: str, color: str = GREEN) -> str:
    return f"{color}{text}{RESET}"


def line(text: str = "", color: str = GREEN) -> None:
    print(c(text, color))


def clear() -> None:
    if _TTY:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def status(text: str, color: str = BGREEN) -> None:
    """Overwrite the current line in place (no scrolling)."""
    if _TTY:
        sys.stdout.write("\r\033[K" + color + text + RESET)
        sys.stdout.flush()
    else:
        print(text)


def end_status() -> None:
    if _TTY:
        sys.stdout.write("\n")
        sys.stdout.flush()


def prompt(text: str = "> ") -> str:
    return input(c(text, BGREEN))


def banner() -> None:
    w = min(width(), 52)
    rule = "═" * w
    line(rule, GREEN)
    for row in _ART:
        line("  " + row, BGREEN)
    line("  ░▒▓  w i f i   r e c o n   c o n s o l e  ▓▒░", GREEN)
    line(rule, GREEN)
    line("  // v1.0 · endast ditt eget nät · own-network use only", DIM)
    print()


def matrix_rain(duration: float = 2.2) -> None:
    """Brief green character rain. No-op when not on a TTY."""
    if not _TTY:
        return
    size = shutil.get_terminal_size((80, 24))
    cols = min(size.columns, 120)
    rows = min(size.lines, 24)
    charset = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿ0123456789ZＺ$#*+=-_<>/\\|"
    tail = 6
    heads = [random.randint(-rows, rows) for _ in range(cols)]
    speeds = [random.choice((1, 1, 1, 2)) for _ in range(cols)]
    sys.stdout.write(_HIDE + "\033[2J")
    end = time.time() + duration
    try:
        while time.time() < end:
            grid = [[None] * cols for _ in range(rows)]
            for x in range(cols):
                for t in range(tail):
                    y = heads[x] - t
                    if 0 <= y < rows:
                        shade = BGREEN if t == 0 else GREEN if t < 3 else DIM
                        grid[y][x] = shade + random.choice(charset) + RESET
            frame = ["\033[H"]
            for y in range(rows):
                frame.append("".join(cell if cell else " " for cell in grid[y]))
            sys.stdout.write("\n".join(frame))
            sys.stdout.flush()
            for x in range(cols):
                heads[x] += speeds[x]
                if heads[x] - tail > rows and random.random() < 0.08:
                    heads[x] = random.randint(-rows // 2, 0)
            time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(RESET + _SHOW + "\033[2J\033[H")
        sys.stdout.flush()


def intro() -> None:
    matrix_rain()
    clear()
    banner()


def interactive_toggle(rows, title=None):
    """Arrow-key multi-select.

    rows: list of (label, selected_bool). Returns a new list of booleans in the
    same order. Cancelling (q/Esc) returns the original selection unchanged.
    Returns None when stdout is not a TTY, so the caller can fall back to typing.
    """
    if not _TTY or not rows:
        return None
    import os
    import select as _select
    import termios
    import tty

    if title is None:
        title = "↑/↓ stega · [mellanslag] toggla · [enter] klar · [q] avbryt"
    initial = [bool(s) for _, s in rows]
    sel = list(initial)
    cursor = 0
    n = len(rows)

    def render():
        buf = [BOLD + GREEN + title + RESET]
        for i, (label, _) in enumerate(rows):
            box = c("[x]", BGREEN) if sel[i] else c("[ ]", DIM)
            arrow = c("▶", BGREEN) if i == cursor else " "
            body = (BGREEN if i == cursor else GREEN) + label + RESET
            buf.append(f"{arrow} {box} {body}")
        # Clear and redraw from the top each keypress -- robust to any list
        # height and to terminal scrolling (no cursor-up arithmetic).
        sys.stdout.write("\033[2J\033[H" + "\n".join(buf) + "\n")
        sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    sys.stdout.write(_HIDE)

    def read_key():
        # Read the raw fd, not buffered sys.stdin: otherwise Python's input
        # buffer swallows the "[A" tail of an arrow key and we see a bare Esc.
        b = os.read(fd, 1)
        if b == b"\x1b":
            ready, _, _ = _select.select([fd], [], [], 0.05)
            if ready:
                b += os.read(fd, 2)
        return b

    try:
        # cbreak (not raw): key-at-a-time, no echo, but keep output NL->CR-LF
        # mapping so redraws land at column 0 instead of staircasing.
        tty.setcbreak(fd)
        render()
        try:
            while True:
                key = read_key()
                if not key:
                    break
                if key == b"\x1b[A" or key in (b"k", b"K"):
                    cursor = (cursor - 1) % n
                elif key == b"\x1b[B" or key in (b"j", b"J"):
                    cursor = (cursor + 1) % n
                elif key == b" ":
                    sel[cursor] = not sel[cursor]
                elif key in (b"\r", b"\n"):
                    break
                elif key in (b"q", b"Q", b"\x03", b"\x1b"):
                    sel = list(initial)  # q / Ctrl-C / bare Esc = cancel
                    break
                render()
        except KeyboardInterrupt:
            sel = list(initial)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write(_SHOW + "\n")
        sys.stdout.flush()
    return sel
