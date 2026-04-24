"""
Scapy initialization for sandboxed/containerized environments.
Patches scapy's IPv6 route reading to tolerate missing 'scope' fields
in network interface address data (common in gVisor/Docker).
Import this module BEFORE any scapy imports in main.py.
"""
import importlib
import sys


def _patch_scapy_rtnetlink():
    """
    Patch scapy.arch.linux.rtnetlink.read_routes6 inline.
    The original code does x["scope"] which fails when the kernel
    doesn't provide scope info. We replace with x.get("scope", 0).
    """
    try:
        spec = importlib.util.find_spec("scapy.arch.linux.rtnetlink")
        if spec is None or spec.origin is None:
            return

        with open(spec.origin, 'r') as f:
            src = f.read()

        if 'x["scope"]' in src and 'x.get("scope"' not in src:
            patched = src.replace('x["scope"]', 'x.get("scope", 0)')
            with open(spec.origin, 'w') as f:
                f.write(patched)
    except Exception:
        pass


_patch_scapy_rtnetlink()
