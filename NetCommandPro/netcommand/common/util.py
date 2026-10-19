"""Utilidades pequeñas sin dependencias externas."""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import socket
import sys
import time
from typing import Any


def now() -> float:
    return time.time()


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def loads(text: str | None, default: Any = None) -> Any:
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if is_windows():  # pragma: no cover
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexchars = "".join(c for c in mac if c.isalnum()).lower()
    if len(hexchars) != 12 or any(c not in "0123456789abcdef" for c in hexchars):
        return None
    if hexchars in ("000000000000", "ffffffffffff"):
        return None
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2))


def mac_is_locally_administered(mac: str) -> bool:
    first = int(mac.split(":")[0], 16)
    return bool(first & 0x02)


def ip_in_networks(ip: str, networks: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for n in networks:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def local_hostname() -> str:
    return socket.gethostname()


def human_bytes(n: float | int | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
