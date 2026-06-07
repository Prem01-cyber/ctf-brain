"""On-demand full-screen capture, with multiple backends.

Screenshots are optional context. We try whatever capture tool exists and
degrade gracefully (returning None) if none works — common on locked-down
Wayland desktops. The PNG comes back base64-encoded for an Anthropic image block.
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile

from . import config

# Each backend: (binary, argv-template). {out} is replaced with the temp path.
# Ordered Wayland-first, then X11, then desktop-specific helpers.
_BACKENDS: list[tuple[str, list[str]]] = [
    ("grim", ["grim", "{out}"]),                                  # wlroots (sway/hyprland)
    ("grimshot", ["grimshot", "save", "screen", "{out}"]),
    ("spectacle", ["spectacle", "-b", "-n", "-o", "{out}"]),      # KDE
    ("gnome-screenshot", ["gnome-screenshot", "-f", "{out}"]),    # GNOME
    ("scrot", ["scrot", "-o", "{out}"]),                          # X11
    ("maim", ["maim", "{out}"]),                                  # X11
    ("import", ["import", "-window", "root", "{out}"]),           # ImageMagick / X11
]


def available_backend() -> str | None:
    for name, _ in _BACKENDS:
        if shutil.which(name):
            return name
    return None


_probe_cache: bool | None = None


def probe(force: bool = False) -> bool:
    """Whether capture actually *works* here (cached after the first attempt).

    A binary existing (e.g. ImageMagick `import`) doesn't mean it can grab the
    screen — X11 tools fail on Wayland. This does one real capture to find out.
    """
    global _probe_cache
    if _probe_cache is None or force:
        _probe_cache = capture() is not None
    return _probe_cache


def capture() -> bytes | None:
    """Capture the screen and return PNG bytes, or None if no backend works."""
    fd, path = tempfile.mkstemp(suffix=".png", prefix="ctf_snap_")
    os.close(fd)
    try:
        for name, template in _BACKENDS:
            if not shutil.which(name):
                continue
            argv = [path if part == "{out}" else part for part in template]
            try:
                subprocess.run(
                    argv,
                    check=True,
                    timeout=10,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except (subprocess.SubprocessError, OSError):
                continue
            if os.path.getsize(path) > 0:
                with open(path, "rb") as f:
                    return f.read()
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def capture_b64() -> str | None:
    raw = capture()
    return base64.b64encode(raw).decode() if raw else None


def flag_requested() -> bool:
    """True if a WM hotkey touched the flag file. Clears it as a side effect."""
    if os.path.exists(config.SCREENSHOT_FLAG):
        try:
            os.remove(config.SCREENSHOT_FLAG)
        except OSError:
            pass
        return True
    return False
