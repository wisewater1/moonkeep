"""
Capability detection helpers.

Plugins call these to find out what they can actually do in the current
environment (root or not, real wireless card or not, aircrack-ng installed
or not, ...) so they can degrade gracefully on phones, CI runners, and
non-privileged user shells instead of crashing the whole backend.

All checks are fast and cached for the lifetime of the process.
"""

from __future__ import annotations

import os
import shutil
import socket
import functools
from typing import Iterable, Optional


@functools.lru_cache(maxsize=1)
def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows / non-POSIX
        return False


@functools.lru_cache(maxsize=64)
def has_binary(name: str) -> bool:
    """Return True if `name` is on PATH and executable."""
    return shutil.which(name) is not None


@functools.lru_cache(maxsize=1)
def list_interfaces() -> tuple[str, ...]:
    """All network interfaces visible to the kernel."""
    try:
        return tuple(sorted(os.listdir("/sys/class/net")))
    except Exception:
        return ()


def has_interface(name: Optional[str]) -> bool:
    """True if /sys/class/net/<name> exists. Empty/None → False."""
    if not name:
        return False
    return name in list_interfaces()


@functools.lru_cache(maxsize=1)
def first_wireless_interface() -> Optional[str]:
    """First wlan*/wlp*/wlx* interface, if any."""
    for iface in list_interfaces():
        if iface.startswith(("wlan", "wlp", "wlx")):
            return iface
    return None


@functools.lru_cache(maxsize=1)
def first_ethernet_interface() -> Optional[str]:
    """First non-loopback, non-wireless interface, if any."""
    for iface in list_interfaces():
        if iface == "lo" or iface.startswith(("wlan", "wlp", "wlx", "tun", "tap", "docker", "br-", "veth")):
            continue
        return iface
    return None


@functools.lru_cache(maxsize=1)
def can_send_raw_packets() -> bool:
    """Quick proxy for 'scapy.sendp/send will not raise PermissionError'."""
    if not is_root():
        # Linux capabilities CAP_NET_RAW would also work, but it's hard to
        # check portably; conservative answer is "only if root".
        return False
    return True


def capability_summary() -> dict:
    """Snapshot of detected capabilities, for /capabilities or similar."""
    return {
        "root":              is_root(),
        "raw_packets":       can_send_raw_packets(),
        "interfaces":        list(list_interfaces()),
        "wireless_iface":    first_wireless_interface(),
        "ethernet_iface":    first_ethernet_interface(),
        "binaries": {
            "aircrack-ng": has_binary("aircrack-ng"),
            "hashcat":     has_binary("hashcat"),
            "hostapd":     has_binary("hostapd"),
            "freeradius":  has_binary("freeradius"),
            "tcpdump":     has_binary("tcpdump"),
            "nmap":        has_binary("nmap"),
        },
    }


def degraded_response(reason: str, **extra) -> dict:
    """Standard shape for 'tool ran but had nothing to do here' results."""
    return {"status": "degraded", "reason": reason, "available": False, **extra}
